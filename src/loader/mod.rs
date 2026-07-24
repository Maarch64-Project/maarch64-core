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
        let data = std::fs::read(&path)
            .map_err(|e| crate::Error::LoadError(format!("Failed to read file: {}", e)))?;
        
        let file = object::File::parse(&*data)
            .map_err(|e| crate::Error::LoadError(format!("ELF parse error: {}", e)))?;

        let entry_point = file.entry();
        tracing::info!("ELF Entry point: {:#x}", entry_point);

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
        }

        // Allocate 2MB stack for target process
        let stack_top: u64 = 0x7ffff0000000;
        let stack_size: usize = 0x200000; // 2MB
        let stack_base = stack_top - (stack_size as u64);
        mem.map_anonymous(stack_base, stack_size)?;

        Ok(LoadedBinary {
            entry_point,
            stack_pointer: stack_top - 0x1000,
        })
    }
}
