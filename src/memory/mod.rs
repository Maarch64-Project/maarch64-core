use crate::Result;
use nix::sys::mman::{mmap_anonymous, mprotect, munmap, MapFlags, ProtFlags};
use std::num::NonZeroUsize;
use std::ptr::NonNull;

pub const PAGE_SIZE: usize = 4096;

pub fn align_down_page(addr: u64) -> u64 {
    addr & !((PAGE_SIZE as u64) - 1)
}

pub fn align_up_page(addr: u64) -> u64 {
    (addr + (PAGE_SIZE as u64) - 1) & !((PAGE_SIZE as u64) - 1)
}

pub struct MemorySegment {
    pub addr: u64,
    pub size: usize,
    pub prot: ProtFlags,
    ptr: NonNull<std::ffi::c_void>,
}

impl MemorySegment {
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr() as *const u8, self.size) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr() as *mut u8, self.size) }
    }
}

pub struct MemoryManager {
    segments: Vec<MemorySegment>,
    pub brk_base: u64,
    pub brk_current: u64,
}

impl MemoryManager {
    pub fn new() -> Self {
        Self {
            segments: Vec::new(),
            brk_base: 0,
            brk_current: 0,
        }
    }

    pub fn set_brk_base(&mut self, base: u64) {
        let aligned_base = align_up_page(base);
        self.brk_base = aligned_base;
        self.brk_current = aligned_base;
    }

    pub fn set_brk(&mut self, new_brk: u64) -> Result<u64> {
        if new_brk == 0 || new_brk < self.brk_base {
            return Ok(self.brk_current);
        }

        if new_brk > self.brk_current {
            let cur_aligned = align_up_page(self.brk_current);
            let new_aligned = align_up_page(new_brk);
            let expand_size = (new_aligned - cur_aligned) as usize;

            if expand_size > 0 {
                let mapped = self.map_anonymous_prot(
                    cur_aligned,
                    expand_size,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                )?;
                tracing::info!("Expanded heap brk from {:#x} to {:#x} (mapped {:#x})", self.brk_current, new_brk, mapped);
            }
        }

        self.brk_current = new_brk;
        Ok(self.brk_current)
    }

    pub fn map_anonymous(&mut self, target_addr: u64, size: usize) -> Result<u64> {
        let default_prot = ProtFlags::PROT_READ | ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC;
        self.map_anonymous_prot(target_addr, size, default_prot)
    }

    pub fn map_anonymous_prot(&mut self, target_addr: u64, size: usize, prot: ProtFlags) -> Result<u64> {
        let non_zero_size = NonZeroUsize::new(size)
            .ok_or_else(|| crate::Error::MemoryError("Size cannot be zero".into()))?;

        let flags = MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS;
        let target_non_zero = NonZeroUsize::new(target_addr as usize);

        let ptr = unsafe {
            mmap_anonymous(
                target_non_zero,
                non_zero_size,
                prot,
                flags,
            )
            .map_err(|e| crate::Error::MemoryError(e.to_string()))?
        };

        let segment_virt_addr = if target_addr != 0 { target_addr } else { ptr.as_ptr() as u64 };
        self.segments.push(MemorySegment {
            addr: segment_virt_addr,
            size,
            prot,
            ptr,
        });

        Ok(segment_virt_addr)
    }

    pub fn mprotect(&mut self, addr: u64, size: usize, prot: ProtFlags) -> Result<()> {
        let aligned_addr = align_down_page(addr);
        let aligned_size = (align_up_page(addr + size as u64) - aligned_addr) as usize;

        for seg in &mut self.segments {
            if seg.addr == aligned_addr && seg.size >= aligned_size {
                unsafe {
                    mprotect(seg.ptr, aligned_size, prot)
                        .map_err(|e| crate::Error::MemoryError(e.to_string()))?;
                }
                seg.prot = prot;
                return Ok(());
            }
        }

        Err(crate::Error::MemoryError(format!(
            "No mapped segment matching address {:#x}",
            addr
        )))
    }

    pub fn munmap(&mut self, addr: u64, size: usize) -> Result<()> {
        let aligned_addr = align_down_page(addr);
        let aligned_size = (align_up_page(addr + size as u64) - aligned_addr) as usize;

        if let Some(pos) = self.segments.iter().position(|seg| seg.addr == aligned_addr) {
            let seg = self.segments.remove(pos);
            unsafe {
                munmap(seg.ptr, aligned_size)
                    .map_err(|e| crate::Error::MemoryError(e.to_string()))?;
            }
            return Ok(());
        }

        Err(crate::Error::MemoryError(format!(
            "No mapped segment to unmap at {:#x}",
            addr
        )))
    }

    pub fn write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        for seg in &mut self.segments {
            if addr >= seg.addr && addr + (data.len() as u64) <= seg.addr + (seg.size as u64) {
                let offset = (addr - seg.addr) as usize;
                let slice = seg.as_mut_slice();
                slice[offset..offset + data.len()].copy_from_slice(data);
                return Ok(());
            }
        }
        Err(crate::Error::MemoryError(format!(
            "Address {:#x} out of mapped memory bounds",
            addr
        )))
    }

    pub fn read(&self, addr: u64, len: usize) -> Result<&[u8]> {
        for seg in &self.segments {
            if addr >= seg.addr && addr + (len as u64) <= seg.addr + (seg.size as u64) {
                let offset = (addr - seg.addr) as usize;
                return Ok(&seg.as_slice()[offset..offset + len]);
            }
        }
        Err(crate::Error::MemoryError(format!(
            "Address {:#x} out of mapped memory bounds",
            addr
        )))
    }

    pub fn get_host_ptr(&self, addr: u64) -> Result<*const u8> {
        for seg in &self.segments {
            if addr >= seg.addr && addr < seg.addr + (seg.size as u64) {
                let offset = (addr - seg.addr) as usize;
                return Ok(unsafe { (seg.ptr.as_ptr() as *const u8).add(offset) });
            }
        }
        Err(crate::Error::MemoryError(format!(
            "Address {:#x} out of mapped memory bounds",
            addr
        )))
    }
}
