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

            if vaddr + (size as u64) > max_vaddr {
                max_vaddr = vaddr + (size as u64);
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

        // Push 16 random bytes for AT_RANDOM
        sp -= 16;
        let random_bytes_ptr = sp;
        let random_bytes: [u8; 16] = [0x42; 16];
        mem.write(random_bytes_ptr, &random_bytes)?;

        // Align SP to 16-byte boundary
        sp &= !0xf;

        // Auxv Entries (key, val)
        let auxv: &[(u64, u64)] = &[
            (6, 4096),                  // AT_PAGESZ
            (9, entry_point),            // AT_ENTRY
            (25, random_bytes_ptr),      // AT_RANDOM
            (0, 0),                      // AT_NULL
        ];

        // Push auxv in reverse order
        for &(key, val) in auxv.iter().rev() {
            sp -= 8;
            mem.write(sp, &val.to_le_bytes())?;
            sp -= 8;
            mem.write(sp, &key.to_le_bytes())?;
        }

        // envp (null)
        sp -= 8;
        mem.write(sp, &0u64.to_le_bytes())?;

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

        Ok(LoadedBinary {
            entry_point,
            stack_pointer: sp,
        })
    }
}
