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
    pub brk_mapped_end: u64,
    pub mmap_current: u64,
}

impl MemoryManager {
    pub fn new() -> Self {
        Self {
            segments: Vec::new(),
            brk_base: 0,
            brk_current: 0,
            brk_mapped_end: 0,
            mmap_current: 0x7000_0000_0000,
        }
    }

    pub fn set_brk_base(&mut self, base: u64) {
        let aligned_base = align_up_page(base);
        self.brk_base = aligned_base;
        self.brk_current = aligned_base;
        self.brk_mapped_end = aligned_base;
    }

    pub fn set_brk(&mut self, new_brk: u64) -> Result<u64> {
        if new_brk == 0 || new_brk < self.brk_base {
            return Ok(self.brk_current);
        }

        if new_brk > self.brk_mapped_end {
            let cur_mapped = self.brk_mapped_end;
            let new_mapped = align_up_page(new_brk);
            let expand_size = (new_mapped - cur_mapped) as usize;

            if expand_size > 0 {
                let mapped = self.map_anonymous_prot(
                    cur_mapped,
                    expand_size,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                )?;
                self.brk_mapped_end = new_mapped;
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
        let mut bytes_written = 0;
        while bytes_written < data.len() {
            let cur_addr = addr + bytes_written as u64;
            let remaining = data.len() - bytes_written;
            let mut chunk_written = 0;
            for seg in &mut self.segments {
                if cur_addr >= seg.addr && cur_addr < seg.addr + (seg.size as u64) {
                    let offset = (cur_addr - seg.addr) as usize;
                    let avail = seg.size - offset;
                    let to_write = remaining.min(avail);
                    let slice = seg.as_mut_slice();
                    slice[offset..offset + to_write].copy_from_slice(&data[bytes_written..bytes_written + to_write]);
                    chunk_written = to_write;
                    break;
                }
            }
            if chunk_written == 0 {
                let seg_info = self.segments.iter().map(|s| format!("[{:#x}..{:#x}]", s.addr, s.addr + s.size as u64)).collect::<Vec<_>>().join(", ");
                return Err(crate::Error::MemoryError(format!(
                    "Address {:#x} (len {}) out of mapped bounds. Segments: {}",
                    addr, data.len(), seg_info
                )));
            }
            bytes_written += chunk_written;
        }
        Ok(())
    }

    pub fn read(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }
        for seg in &self.segments {
            if addr >= seg.addr && addr + (len as u64) <= seg.addr + (seg.size as u64) {
                let offset = (addr - seg.addr) as usize;
                return Ok(seg.as_slice()[offset..offset + len].to_vec());
            }
        }
        let mut buf = vec![0u8; len];
        let mut bytes_read = 0;
        while bytes_read < len {
            let cur_addr = addr + bytes_read as u64;
            let remaining = len - bytes_read;
            let mut chunk_read = 0;
            for seg in &self.segments {
                if cur_addr >= seg.addr && cur_addr < seg.addr + (seg.size as u64) {
                    let offset = (cur_addr - seg.addr) as usize;
                    let avail = seg.size - offset;
                    let to_read = remaining.min(avail);
                    buf[bytes_read..bytes_read + to_read].copy_from_slice(&seg.as_slice()[offset..offset + to_read]);
                    chunk_read = to_read;
                    break;
                }
            }
            if chunk_read == 0 {
                let seg_info = self.segments.iter().map(|s| format!("[{:#x}..{:#x}]", s.addr, s.addr + s.size as u64)).collect::<Vec<_>>().join(", ");
                return Err(crate::Error::MemoryError(format!(
                    "Address {:#x} (len {}) out of mapped bounds. Segments: {}",
                    addr, len, seg_info
                )));
            }
            bytes_read += chunk_read;
        }
        Ok(buf)
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

    pub fn read_string(&self, addr: u64) -> Result<Vec<u8>> {
        let mut cur = addr;
        let mut bytes = Vec::new();
        loop {
            let b = self.read(cur, 1)?[0];
            if b == 0 {
                break;
            }
            bytes.push(b);
            cur += 1;
        }
        Ok(bytes)
    }
}
