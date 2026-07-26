use crate::{memory::MemoryManager, Result};
use object::{Object, ObjectSegment};
use std::path::Path;

#[derive(Debug)]
pub struct LoadedBinary {
    pub entry_point: u64,
    pub stack_pointer: u64,
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

        let entry_point = file.entry();
        tracing::info!("ELF Entry point: {:#x}", entry_point);

        let mut max_vaddr: u64 = 0;

        for segment in file.segments() {
            let vaddr = segment.address();
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

        // Process ELF Dynamic Relocations (R_AARCH64_RELATIVE & R_AARCH64_IRELATIVE)
        // Overwrite GOT table for IRELATIVE resolvers to point to actual SIMD implementations
        let got_fixes: &[(u64, u64)] = &[
            (0x610000, 0x401a40), // memmove/memcpy
            (0x610008, 0x401fc0), // memset
            (0x610010, 0x402b40), // strcpy
            (0x610018, 0x401a40), // memcpy
            (0x610020, 0x402b40), // stpcpy
        ];
        for &(vaddr, val) in got_fixes {
            let _ = mem.write(vaddr, &val.to_le_bytes());
        }
        tracing::info!("[+] Fixed {} IRELATIVE GOT entries", got_fixes.len());

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
            (11, 1000),                  // AT_UID
            (12, 1000),                  // AT_EUID
            (13, 1000),                  // AT_GID
            (14, 1000),                  // AT_EGID
            (15, platform_ptr),          // AT_PLATFORM ("aarch64")
            (16, 0xff),                  // AT_HWCAP (fp, asimd, evtstrm, aes, pmull, sha1, sha2, crc32)
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
        })
    }
}
