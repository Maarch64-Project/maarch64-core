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
        let data = std::fs::read(&path)
            .map_err(|e| Error::LoadError(format!("Failed to read Mach-O file: {}", e)))?;

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

        // Map 128KB Thunk Trampoline & Data Symbol page at 0x7f000000
        let _ = mem.map_anonymous(0x7f000000, 0x20000);
        // Map 64KB TLS page at 0x7f020000
        let _ = mem.map_anonymous(0x7f020000, 0x10000);

        mem.set_brk_base(max_vaddr);

        // Allocate 2MB stack for Darwin process
        let stack_top: u64 = 0x7ffff0000000;
        let stack_size: usize = 0x200000; // 2MB
        let stack_base = stack_top - (stack_size as u64);
        mem.map_anonymous(stack_base, stack_size)?;

        let mut sp = stack_top - 0x1000;

        // Push argument strings onto stack
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

        // Push envp null, argv null, argv pointers, argc (macOS Darwin ABI)
        sp -= 8;
        mem.write(sp, &0u64.to_le_bytes())?; // envp null

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
}
