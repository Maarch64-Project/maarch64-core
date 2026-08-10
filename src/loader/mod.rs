use crate::{memory::MemoryManager, Result, Error};
use object::{Object, ObjectSegment, ObjectSymbol};
use std::path::Path;

pub mod macho;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TargetOs {
    #[default]
    Linux,
    Darwin,
    Android,
}

#[derive(Debug)]
pub struct LoadedBinary {
    pub entry_point: u64,
    pub stack_pointer: u64,
    pub dynamic_thunks: Vec<(u64, String)>,
    pub target_os: TargetOs,
}

pub struct ElfLoader;

impl ElfLoader {
    pub fn load_file<P: AsRef<Path>>(
        path: P,
        mem: &mut MemoryManager,
    ) -> Result<LoadedBinary> {
        let path_str = path.as_ref().to_string_lossy().to_string();
        Self::load_file_with_args(path, &[&path_str], mem)
    }

    pub fn load_file_with_args<P: AsRef<Path>>(
        path: P,
        args: &[&str],
        mem: &mut MemoryManager,
    ) -> Result<LoadedBinary> {
        let data = std::fs::read(&path)
            .map_err(|e| crate::Error::LoadError(format!("Failed to read file: {}", e)))?;
        
        let file = object::File::parse(&*data)
            .map_err(|e| crate::Error::LoadError(format!("ELF parse error: {}", e)))?;

        let is_pie = file.segments().next().map(|s| s.address()).unwrap_or(0) == 0;
        let load_bias: u64 = if is_pie { 0x400000 } else { 0 };

        let mut entry_point = file.entry() + load_bias;
        if file.entry() == 0 {
            use object::ObjectSymbol;
            for sym in file.symbols().chain(file.dynamic_symbols()) {
                if let Ok(name) = sym.name() {
                    if name == "main" || name == "JNI_OnLoad" || name == "ANativeActivity_onCreate" {
                        entry_point = sym.address() + load_bias;
                        tracing::info!("Found exported shared library entry symbol '{}' at {:#x}", name, entry_point);
                        break;
                    }
                }
            }
        }
        tracing::info!("ELF Entry point: {:#x} (load_bias: {:#x})", entry_point, load_bias);

        let mut max_vaddr: u64 = 0;

        for segment in file.segments() {
            let vaddr = segment.address() + load_bias;
            let size = segment.size() as usize;
            if size == 0 {
                continue;
            }

            let segment_data = segment.data()
                .map_err(|e| crate::Error::LoadError(format!("Segment data error: {}", e)))?;

            tracing::info!(
                "Loading ELF Segment: vaddr={:#x}, size={:#x}, data_len={:#x}",
                vaddr,
                size,
                segment_data.len()
            );

            let page_size = 4096;
            let aligned_vaddr = vaddr & !(page_size - 1);
            let offset = (vaddr - aligned_vaddr) as usize;
            let total_size = ((size + offset + (page_size as usize - 1)) / page_size as usize) * page_size as usize;

            mem.map_anonymous(aligned_vaddr, total_size)?;
            mem.write(vaddr, segment_data)?;
            if size > segment_data.len() {
                let bss_size = size - segment_data.len();
                let zeros = vec![0u8; bss_size];
                mem.write(vaddr + segment_data.len() as u64, &zeros)?;
            }

            if vaddr + (size as u64) > max_vaddr {
                max_vaddr = vaddr + (size as u64);
            }
        }

        let mut dynamic_thunks = Vec::new();

        let _ = mem.map_anonymous(0x7f000000, 0x20000);
        let _ = mem.map_anonymous(0x7f020000, 0x10000);
        let _ = mem.write(0x7f010300, &1u32.to_le_bytes());
        let _ = mem.write(0x7f010310, &1u32.to_le_bytes());

        use object::{Object, ObjectSegment, ObjectSymbol};
        let dyn_syms: Vec<_> = file.dynamic_symbols().collect();
        if let Some(relocs) = file.dynamic_relocations() {
            let mut reloc_count = 0;
            let mut symbol_map: std::collections::HashMap<String, u64> = std::collections::HashMap::new();

            for (addr, reloc) in relocs {
                let target_addr = addr + load_bias;
                let target = reloc.target();
                if let object::RelocationTarget::Symbol(sym_idx) = target {
                    let sym_opt = dyn_syms.iter().find(|s| s.index() == sym_idx);
                    if let Some(sym) = sym_opt {
                        if sym.is_undefined() {
                            if let Ok(name) = sym.name() {
                                if !name.is_empty() {
                                    let data_sym_val: u64 = match name {
                                        "stdout" => 0x7f010000,
                                        "stderr" => 0x7f010100,
                                        "stdin" => 0x7f010200,
                                        "optind" => 0x7f010300,
                                        "optarg" => 0x7f010308,
                                        "opterr" => 0x7f010310,
                                        "optopt" => 0x7f010318,
                                        "environ" => 0x7f010400,
                                        _ => 0,
                                    };
                                    if data_sym_val != 0 {
                                        let _ = mem.write(target_addr, &data_sym_val.to_le_bytes());
                                        continue;
                                    }

                                    let next_idx = symbol_map.len() as u64;
                                    let tramp_addr = *symbol_map.entry(name.to_string()).or_insert_with(|| {
                                        let a = 0x7f000000 + next_idx * 8;
                                        dynamic_thunks.push((a, name.to_string()));
                                        a
                                    });
                                    let _ = mem.write(target_addr, &tramp_addr.to_le_bytes());
                                    continue;
                                }
                            }
                        } else if sym.address() != 0 {
                            let addend = reloc.addend() as u64;
                            let val = sym.address() + load_bias + addend;
                            let _ = mem.write(target_addr, &val.to_le_bytes());
                            reloc_count += 1;
                            continue;
                        }
                    }
                }

                let addend = reloc.addend() as u64;
                let val = load_bias.wrapping_add(addend);
                if target_addr == 0x41fef8 {
                    tracing::info!("[TARGET_ADDR 0x41fef8] relative/other val={:#x}", val);
                }
                let _ = mem.write(target_addr, &val.to_le_bytes());
                reloc_count += 1;
            }
        }

        // Handle SHT_RELR / DT_RELR packed relative relocations if present
        if let object::File::Elf64(elf) = &file {
            use object::elf::*;
            use object::read::elf::SectionHeader;
            let endian = elf.endian();
            let sections = elf.elf_section_table();
            for section in sections.iter() {
                if section.sh_type(endian) == SHT_RELR {
                    if let Ok(data) = section.data(endian, elf.data()) {
                        let mut base_addr: u64 = 0;
                        for chunk in data.chunks_exact(8) {
                            let entry = u64::from_le_bytes(chunk.try_into().unwrap());
                            if entry & 1 == 0 {
                                base_addr = entry;
                                let target_addr = base_addr + load_bias;
                                if let Ok(existing) = mem.read(target_addr, 8) {
                                    let curr_val = u64::from_le_bytes(existing.try_into().unwrap());
                                    let new_val = curr_val.wrapping_add(load_bias);
                                    let _ = mem.write(target_addr, &new_val.to_le_bytes());
                                }
                                base_addr += 8;
                            } else {
                                let mut bitmap = entry >> 1;
                                let mut addr = base_addr;
                                while bitmap != 0 {
                                    if bitmap & 1 != 0 {
                                        let target_addr = addr + load_bias;
                                        if let Ok(existing) = mem.read(target_addr, 8) {
                                            let curr_val = u64::from_le_bytes(existing.try_into().unwrap());
                                            let new_val = curr_val.wrapping_add(load_bias);
                                            let _ = mem.write(target_addr, &new_val.to_le_bytes());
                                        }
                                    }
                                    bitmap >>= 1;
                                    addr += 8;
                                }
                                base_addr += 63 * 8;
                            }
                        }
                    }
                }
            }
        }

        mem.set_brk_base(max_vaddr);

        let stack_top: u64 = 0x7ffff0000000;
        let stack_size: usize = 0x200000;
        let stack_base = stack_top - (stack_size as u64);
        mem.map_anonymous(stack_base, stack_size)?;

        let mut sp = stack_top - 0x1000;

        let mut arg_ptrs = Vec::new();
        for arg in args {
            let bytes = arg.as_bytes();
            sp -= (bytes.len() + 1) as u64;
            mem.write(sp, bytes)?;
            mem.write(sp + bytes.len() as u64, &[0u8])?;
            arg_ptrs.push(sp);
        }

        let env_vars = [
            "PATH=/usr/local/bin:/usr/bin:/bin",
            "TERM=xterm-256color",
            "HOME=/root",
            "SHELL=/bin/sh",
            "PWD=/",
        ];
        let mut env_ptrs = Vec::new();
        for env in &env_vars {
            let bytes = env.as_bytes();
            sp -= (bytes.len() + 1) as u64;
            mem.write(sp, bytes)?;
            mem.write(sp + bytes.len() as u64, &[0u8])?;
            env_ptrs.push(sp);
        }

        let platform_str = b"aarch64\0";
        sp -= platform_str.len() as u64;
        mem.write(sp, platform_str)?;
        let platform_ptr = sp;

        sp -= 16;
        let random_bytes_ptr = sp;
        let random_bytes: [u8; 16] = [0x42; 16];
        mem.write(random_bytes_ptr, &random_bytes)?;

        sp &= !0xf;

        let e_phoff = u64::from_le_bytes(data[32..40].try_into().unwrap());
        let e_phentsize = u16::from_le_bytes(data[54..56].try_into().unwrap()) as u64;
        let e_phnum = u16::from_le_bytes(data[56..58].try_into().unwrap()) as u64;
        let at_phdr = 0x400000 + e_phoff;

        let auxv: &[(u64, u64)] = &[
            (3, at_phdr),
            (4, e_phentsize),
            (5, e_phnum),
            (6, 4096),
            (7, 0),
            (8, 0),
            (9, entry_point),
            (11, 0),
            (12, 0),
            (13, 0),
            (14, 0),
            (15, platform_ptr),
            (16, 0),
            (17, 100),
            (23, 0),
            (25, random_bytes_ptr),
            (26, 0),
            (0, 0),
        ];

        let total_words = 1 + arg_ptrs.len() + 1 + env_ptrs.len() + 1 + auxv.len() * 2;
        if total_words % 2 != 0 {
            sp -= 8;
        }

        for &(key, val) in auxv.iter().rev() {
            sp -= 8;
            mem.write(sp, &val.to_le_bytes())?;
            sp -= 8;
            mem.write(sp, &key.to_le_bytes())?;
        }

        sp -= 8;
        mem.write(sp, &0u64.to_le_bytes())?;

        for &ptr in env_ptrs.iter().rev() {
            sp -= 8;
            mem.write(sp, &ptr.to_le_bytes())?;
        }

        sp -= 8;
        mem.write(sp, &0u64.to_le_bytes())?;

        for &ptr in arg_ptrs.iter().rev() {
            sp -= 8;
            mem.write(sp, &ptr.to_le_bytes())?;
        }

        sp -= 8;
        let argc = arg_ptrs.len() as u64;
        mem.write(sp, &argc.to_le_bytes())?;

        Ok(LoadedBinary {
            entry_point,
            stack_pointer: sp,
            dynamic_thunks,
            target_os: TargetOs::Linux,
        })
    }
}

pub struct AutoLoader;

impl AutoLoader {
    pub fn load_file_with_args<P: AsRef<Path>>(
        path: P,
        args: &[&str],
        mem: &mut MemoryManager,
    ) -> Result<LoadedBinary> {
        let data = std::fs::read(&path)
            .map_err(|e| Error::LoadError(format!("Failed to read file: {}", e)))?;

        if data.len() < 4 {
            return Err(Error::LoadError("Binary file too small".into()));
        }

        let magic = &data[0..4];
        if magic == b"\x7fELF" {
            tracing::info!("[AutoLoader] Detected Linux ELF binary");
            ElfLoader::load_file_with_args(path, args, mem)
        } else if magic == &[0xcf, 0xfa, 0xed, 0xfe] || magic == &[0xfe, 0xed, 0xfa, 0xcf] || magic == &[0xca, 0xfe, 0xba, 0xbe] {
            tracing::info!("[AutoLoader] Detected macOS Mach-O binary");
            macho::MachOLoader::load_file_with_args(path, args, mem)
        } else {
            // Default to ELF attempt
            ElfLoader::load_file_with_args(path, args, mem)
        }
    }
}
