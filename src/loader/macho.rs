use crate::{memory::MemoryManager, Result, Error};
use object::{Object, ObjectSegment, ObjectSymbol};
use std::path::Path;
use super::{LoadedBinary, TargetOs};

pub struct MachOLoader;

impl MachOLoader {
    pub fn load_file_with_args<P: AsRef<Path>>(
        path: P,
        args: &[&str],
        mem: &mut MemoryManager,
    ) -> Result<LoadedBinary> {
        let raw_data = std::fs::read(&path)
            .map_err(|e| Error::LoadError(format!("Failed to read Mach-O file: {}", e)))?;

        let data = Self::extract_arm64_slice(&raw_data)?;

        let file = object::File::parse(&*data)
            .map_err(|e| Error::LoadError(format!("Mach-O parse error: {}", e)))?;

        let is_pie = true;
        let load_bias: u64 = if is_pie { 0x100000000 } else { 0 };

        let entry_point = file.entry() + load_bias;
        tracing::info!("[Mach-O Loader] Entry point: {:#x} (load_bias: {:#x})", entry_point, load_bias);

        let mut max_vaddr: u64 = 0;

        for segment in file.segments() {
            let vaddr = segment.address() + load_bias;
            let size = segment.size() as usize;
            if size == 0 {
                continue;
            }

            let segment_data = segment.data()
                .map_err(|e| Error::LoadError(format!("Segment data error: {}", e)))?;

            tracing::info!(
                "[Mach-O Loader] Loading Segment: vaddr={:#x}, size={:#x}, data_len={:#x}",
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
        let mut symbol_map: std::collections::HashMap<String, u64> = std::collections::HashMap::new();

        // Map 128KB Thunk Trampoline page at 0x7f000000
        let _ = mem.map_anonymous(0x7f000000, 0x20000);
        // Map 64KB TLS page at 0x7f020000
        let _ = mem.map_anonymous(0x7f020000, 0x10000);

        // Resolve Mach-O dynamic symbols / undefined stubs
        for sym in file.symbols() {
            if sym.is_undefined() {
                if let Ok(name) = sym.name() {
                    if !name.is_empty() {
                        let clean_name = name.strip_prefix('_').unwrap_or(name);
                        let next_idx = symbol_map.len() as u64;
                        let tramp_addr = *symbol_map.entry(clean_name.to_string()).or_insert_with(|| {
                            let a = 0x7f000000 + next_idx * 8;
                            dynamic_thunks.push((a, clean_name.to_string()));
                            a
                        });
                        tracing::debug!("[Mach-O Dynamic Sym] Import {} -> Trampoline {:#x}", clean_name, tramp_addr);
                    }
                }
            }
        }

        mem.set_brk_base(max_vaddr);

        // Allocate 2MB stack for Darwin process
        let stack_top: u64 = 0x7ffff0000000;
        let stack_size: usize = 0x200000;
        let stack_base = stack_top - (stack_size as u64);
        mem.map_anonymous(stack_base, stack_size)?;

        let mut sp = stack_top - 0x1000;

        // Write Darwin Environment & Apple vector strings
        let env_vars = ["PATH=/usr/local/bin:/usr/bin:/bin", "USER=root", "HOME=/root"];
        let mut env_ptrs = Vec::new();
        for env in &env_vars {
            let bytes = env.as_bytes();
            sp -= (bytes.len() + 1) as u64;
            mem.write(sp, bytes)?;
            mem.write(sp + bytes.len() as u64, &[0u8])?;
            env_ptrs.push(sp);
        }

        let exec_path_str = path.as_ref().to_string_lossy();
        let apple_vars = [exec_path_str.as_bytes(), b"pf_random=0123456789abcdef"];
        let mut apple_ptrs = Vec::new();
        for apple in &apple_vars {
            sp -= (apple.len() + 1) as u64;
            mem.write(sp, apple)?;
            mem.write(sp + apple.len() as u64, &[0u8])?;
            apple_ptrs.push(sp);
        }

        let mut arg_ptrs = Vec::new();
        for arg in args {
            let bytes = arg.as_bytes();
            sp -= (bytes.len() + 1) as u64;
            mem.write(sp, bytes)?;
            mem.write(sp + bytes.len() as u64, &[0u8])?;
            arg_ptrs.push(sp);
        }

        // Align SP to 16-byte boundary
        sp &= !0xf;

        // Push Darwin ABI stack: apple null, apple ptrs, envp null, envp ptrs, argv null, argv ptrs, argc
        sp -= 8;
        mem.write(sp, &0u64.to_le_bytes())?; // apple null

        for &ptr in apple_ptrs.iter().rev() {
            sp -= 8;
            mem.write(sp, &ptr.to_le_bytes())?;
        }

        sp -= 8;
        mem.write(sp, &0u64.to_le_bytes())?; // envp null

        for &ptr in env_ptrs.iter().rev() {
            sp -= 8;
            mem.write(sp, &ptr.to_le_bytes())?;
        }

        sp -= 8;
        mem.write(sp, &0u64.to_le_bytes())?; // argv null

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
            target_os: TargetOs::Darwin,
        })
    }

    fn extract_arm64_slice(raw: &[u8]) -> Result<Vec<u8>> {
        if raw.len() < 8 {
            return Ok(raw.to_vec());
        }

        let magic = u32::from_be_bytes(raw[0..4].try_into().unwrap());
        // FAT_MAGIC (0xcafebabe) or FAT_CIGAM (0xbebafeca)
        if magic == 0xcafebabe || magic == 0xbebafeca {
            let nfat_arch = u32::from_be_bytes(raw[4..8].try_into().unwrap()) as usize;
            tracing::info!("[Mach-O Loader] Detected Universal Fat Binary with {} architectures", nfat_arch);

            let mut offset = 8;
            for _ in 0..nfat_arch {
                if offset + 20 > raw.len() {
                    break;
                }
                let cputype = u32::from_be_bytes(raw[offset..offset + 4].try_into().unwrap());
                let slice_offset = u32::from_be_bytes(raw[offset + 8..offset + 12].try_into().unwrap()) as usize;
                let slice_size = u32::from_be_bytes(raw[offset + 12..offset + 16].try_into().unwrap()) as usize;

                // CPU_TYPE_ARM64 = 0x0100000C
                if cputype == 0x0100000C || cputype == 0x0100000E {
                    if slice_offset + slice_size <= raw.len() {
                        tracing::info!("[Mach-O Loader] Found ARM64 slice: offset={:#x}, size={:#x}", slice_offset, slice_size);
                        return Ok(raw[slice_offset..slice_offset + slice_size].to_vec());
                    }
                }
                offset += 20;
            }
        }

        Ok(raw.to_vec())
    }
}
