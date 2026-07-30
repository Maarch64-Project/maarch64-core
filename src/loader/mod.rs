use crate::{memory::MemoryManager, Result};
use object::{Object, ObjectSegment, ObjectSymbol};
use std::path::Path;

#[derive(Debug)]
pub struct LoadedBinary {
    pub entry_point: u64,
    pub stack_pointer: u64,
    pub dynamic_thunks: Vec<(u64, String)>,
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

        let entry_point = file.entry() + load_bias;
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

            // Map page-aligned memory
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

        // Map 128KB Thunk Trampoline & Data Symbol page at 0x7f000000
        let _ = mem.map_anonymous(0x7f000000, 0x20000);
        // Map 64KB TLS (Thread Local Storage) page at 0x7f020000
        let _ = mem.map_anonymous(0x7f020000, 0x10000);
        // Initialize default values for data symbols
        let _ = mem.write(0x7f010300, &1u32.to_le_bytes()); // optind = 1
        let _ = mem.write(0x7f010310, &1u32.to_le_bytes()); // opterr = 1

        // Process ELF Dynamic Relocations (R_AARCH64_RELATIVE & dynamic symbols) for PIE binaries
        if load_bias > 0 {
            let dyn_syms: Vec<_> = file.dynamic_symbols().collect();
            for (idx, ds) in dyn_syms.iter().enumerate() {
                if let Ok(name) = ds.name() {
                    tracing::info!("[dyn_sym] idx={} name={:?} is_undef={}", idx, name, ds.is_undefined());
                }
            }

            if let Some(relocs) = file.dynamic_relocations() {
                let mut reloc_count = 0;
                let mut symbol_map: std::collections::HashMap<String, u64> = std::collections::HashMap::new();

                for (addr, reloc) in relocs {
                    let target_addr = addr + load_bias;
                    let target = reloc.target();
                    if let object::RelocationTarget::Symbol(sym_idx) = target {
                        if let Some(sym) = sym_idx.0.checked_sub(1).and_then(|i| dyn_syms.get(i)) {
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
                                        tracing::info!("[reloc] target_addr={:#x} sym_idx={} name={} tramp_addr={:#x}", target_addr, sym_idx.0, name, tramp_addr);
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
                    let _ = mem.write(target_addr, &val.to_le_bytes());
                    reloc_count += 1;
                }
                tracing::info!("[+] Processed {} dynamic RELATIVE relocations, {} symbol thunks", reloc_count, symbol_map.len());
            }
        }


        // Set brk_base after the highest loaded segment
        mem.set_brk_base(max_vaddr);

        // Allocate 2MB stack for target process
        let stack_top: u64 = 0x7ffff0000000;
        let stack_size: usize = 0x200000; // 2MB
        let stack_base = stack_top - (stack_size as u64);
        mem.map_anonymous(stack_base, stack_size)?;

        let mut sp = stack_top - 0x1000;

        // Push argument strings onto stack
        let mut arg_ptrs = Vec::new();
        for arg in args {
            let bytes = arg.as_bytes();
            sp -= (bytes.len() + 1) as u64; // +1 for null terminator
            mem.write(sp, bytes)?;
            mem.write(sp + bytes.len() as u64, &[0u8])?;
            arg_ptrs.push(sp);
        }

        // Push environment strings onto stack
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

        // Push "aarch64\0" string for AT_PLATFORM
        let platform_str = b"aarch64\0";
        sp -= platform_str.len() as u64;
        mem.write(sp, platform_str)?;
        let platform_ptr = sp;

        // Push 16 random bytes for AT_RANDOM
        sp -= 16;
        let random_bytes_ptr = sp;
        let random_bytes: [u8; 16] = [0x42; 16];
        mem.write(random_bytes_ptr, &random_bytes)?;

        // Align SP to 16-byte boundary
        sp &= !0xf;

        let e_phoff = u64::from_le_bytes(data[32..40].try_into().unwrap());
        let e_phentsize = u16::from_le_bytes(data[54..56].try_into().unwrap()) as u64;
        let e_phnum = u16::from_le_bytes(data[56..58].try_into().unwrap()) as u64;
        let at_phdr = 0x400000 + e_phoff;

        // Auxv Entries (key, val)
        let auxv: &[(u64, u64)] = &[
            (3, at_phdr),                // AT_PHDR (ELF program headers)
            (4, e_phentsize),            // AT_PHENT (size of program header)
            (5, e_phnum),                // AT_PHNUM (number of program headers)
            (6, 4096),                   // AT_PAGESZ
            (7, 0),                      // AT_BASE
            (8, 0),                      // AT_FLAGS
            (9, entry_point),            // AT_ENTRY
            (11, 0),                     // AT_UID
            (12, 0),                     // AT_EUID
            (13, 0),                     // AT_GID
            (14, 0),                     // AT_EGID
            (15, platform_ptr),          // AT_PLATFORM ("aarch64")
            (16, 0),                     // AT_HWCAP (0 = scalar software fallback)
            (17, 100),                   // AT_CLKTCK
            (23, 0),                     // AT_SECURE
            (25, random_bytes_ptr),      // AT_RANDOM
            (26, 0),                     // AT_HWCAP2
            (0, 0),                      // AT_NULL
        ];

        // Total 64-bit words to push: argc (1) + argv (len + 1) + envp (len + 1) + auxv (len * 2)
        let total_words = 1 + arg_ptrs.len() + 1 + env_ptrs.len() + 1 + auxv.len() * 2;
        if total_words % 2 != 0 {
            sp -= 8; // Alignment padding
        }

        // Push auxv in reverse order
        for &(key, val) in auxv.iter().rev() {
            sp -= 8;
            mem.write(sp, &val.to_le_bytes())?;
            sp -= 8;
            mem.write(sp, &key.to_le_bytes())?;
        }

        // envp null terminator
        sp -= 8;
        mem.write(sp, &0u64.to_le_bytes())?;

        // envp pointers in reverse order
        for &ptr in env_ptrs.iter().rev() {
            sp -= 8;
            mem.write(sp, &ptr.to_le_bytes())?;
        }

        // argv null terminator
        sp -= 8;
        mem.write(sp, &0u64.to_le_bytes())?;

        // argv pointers in reverse order
        for &ptr in arg_ptrs.iter().rev() {
            sp -= 8;
            mem.write(sp, &ptr.to_le_bytes())?;
        }

        // argc
        sp -= 8;
        let argc = arg_ptrs.len() as u64;
        mem.write(sp, &argc.to_le_bytes())?;

        // Ensure SP is 16-byte aligned
        debug_assert_eq!(sp % 16, 0);

        for (i, &ptr) in arg_ptrs.iter().enumerate() {
            let str_bytes = mem.read_string(ptr).unwrap_or_default();
            tracing::info!("Loader Arg [{}]: ptr={:#x} str={:?}", i, ptr, String::from_utf8_lossy(&str_bytes));
        }

        Ok(LoadedBinary {
            entry_point,
            stack_pointer: sp,
            dynamic_thunks,
        })
    }
}
