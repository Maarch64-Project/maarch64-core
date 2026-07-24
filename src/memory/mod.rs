use crate::Result;
use nix::sys::mman::{mmap_anonymous, MapFlags, ProtFlags};
use std::num::NonZeroUsize;
use std::ptr::NonNull;

pub struct MemorySegment {
    pub addr: u64,
    pub size: usize,
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
}

impl MemoryManager {
    pub fn new() -> Self {
        Self {
            segments: Vec::new(),
        }
    }

    pub fn map_anonymous(&mut self, target_addr: u64, size: usize) -> Result<u64> {
        let non_zero_size = NonZeroUsize::new(size)
            .ok_or_else(|| crate::Error::MemoryError("Size cannot be zero".into()))?;

        let prot = ProtFlags::PROT_READ | ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC;
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

        let actual_addr = ptr.as_ptr() as u64;
        self.segments.push(MemorySegment {
            addr: actual_addr,
            size,
            ptr,
        });

        Ok(actual_addr)
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
