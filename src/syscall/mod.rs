use crate::{cpu::CpuContext, memory::MemoryManager, Result};

pub struct SyscallDispatcher;

impl SyscallDispatcher {
    pub fn handle_syscall(ctx: &mut CpuContext, mem: &mut MemoryManager) -> Result<i64> {
        let nr = ctx.get_x(8); // ARM64 syscall number is in X8
        tracing::info!("Syscall {} (X0={:#x}, X1={:#x}, X2={:#x})", nr, ctx.get_x(0), ctx.get_x(1), ctx.get_x(2));
        match nr {
            56 => {
                // sys_openat(dfd, filename, flags, mode)
                let dfd = ctx.get_x(0) as i32;
                let path_ptr = ctx.get_x(1);
                let flags = ctx.get_x(2) as i32;
                let mode = ctx.get_x(3) as u32;

                let path_bytes = mem.read_string(path_ptr)?;
                let c_path = std::ffi::CString::new(path_bytes)
                    .map_err(|e| crate::Error::LoadError(e.to_string()))?;

                let res = unsafe {
                    libc::openat(dfd, c_path.as_ptr(), flags, mode)
                };
                let ret = res as i64;
                ctx.set_x(0, ret as u64);
                Ok(ret)
            }
            57 => {
                // sys_close(fd)
                let fd = ctx.get_x(0) as i32;
                let res = unsafe { libc::close(fd) } as i64;
                ctx.set_x(0, res as u64);
                Ok(res)
            }
            63 => {
                // sys_read(fd, buf, count)
                let fd = ctx.get_x(0) as i32;
                let buf_ptr = ctx.get_x(1);
                let count = ctx.get_x(2) as usize;

                let mut tmp_buf = vec![0u8; count];
                let ret = unsafe {
                    libc::read(fd, tmp_buf.as_mut_ptr() as *mut std::ffi::c_void, count)
                };
                if ret > 0 {
                    mem.write(buf_ptr, &tmp_buf[..ret as usize])?;
                }
                let res = ret as i64;
                ctx.set_x(0, res as u64);
                Ok(res)
            }
            64 => {
                // sys_write(fd, buf, count)
                let fd = ctx.get_x(0) as i32;
                let buf_ptr = ctx.get_x(1);
                let count = ctx.get_x(2) as usize;

                let buf = mem.read(buf_ptr, count)?;
                let ret = unsafe {
                    libc::write(fd, buf.as_ptr() as *const std::ffi::c_void, count)
                };
                let res = ret as i64;
                ctx.set_x(0, res as u64);
                Ok(res)
            }
            93 | 94 => {
                // sys_exit / sys_exit_group(status)
                let status = ctx.get_x(0) as i32;
                ctx.exited = true;
                ctx.exit_code = status;
                Ok(status as i64)
            }
            96 => {
                // sys_set_tid_address(ctid)
                let tid = 1000i64;
                ctx.set_x(0, tid as u64);
                Ok(tid)
            }
            113 => {
                // sys_clock_gettime(clk_id, tp)
                let tp_ptr = ctx.get_x(1);
                if tp_ptr != 0 {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default();
                    let sec = now.as_secs();
                    let nsec = now.subsec_nanos() as u64;
                    mem.write(tp_ptr, &sec.to_le_bytes())?;
                    mem.write(tp_ptr + 8, &nsec.to_le_bytes())?;
                }
                ctx.set_x(0, 0);
                Ok(0)
            }
            160 => {
                // sys_uname(buf)
                let buf_ptr = ctx.get_x(0);
                if buf_ptr != 0 {
                    // struct utsname: 6 fields of 65 bytes each (65 * 6 = 390 bytes)
                    let sysname = b"Linux\0";
                    let nodename = b"maarch64\0";
                    let release = b"6.1.0-maarch64\0";
                    let version = b"#1 SMP PREEMPT_DYNAMIC\0";
                    let machine = b"aarch64\0";
                    let domainname = b"(none)\0";

                    let mut uts = [0u8; 390];
                    uts[0..sysname.len()].copy_from_slice(sysname);
                    uts[65..65 + nodename.len()].copy_from_slice(nodename);
                    uts[130..130 + release.len()].copy_from_slice(release);
                    uts[195..195 + version.len()].copy_from_slice(version);
                    uts[260..260 + machine.len()].copy_from_slice(machine);
                    uts[325..325 + domainname.len()].copy_from_slice(domainname);

                    mem.write(buf_ptr, &uts)?;
                }
                ctx.set_x(0, 0);
                Ok(0)
            }
            178 => {
                // sys_gettid()
                let tid = 1000i64;
                ctx.set_x(0, tid as u64);
                Ok(tid)
            }
            214 => {
                // sys_brk(target_brk)
                let target_brk = ctx.get_x(0);
                let new_brk = if target_brk == 0 {
                    mem.brk_current
                } else {
                    mem.set_brk(target_brk)?
                };
                ctx.set_x(0, new_brk);
                Ok(new_brk as i64)
            }
            215 => {
                // sys_munmap(addr, length)
                let addr = ctx.get_x(0);
                let len = ctx.get_x(1) as usize;
                mem.munmap(addr, len)?;
                ctx.set_x(0, 0);
                Ok(0)
            }
            222 => {
                // sys_mmap(addr, len, prot, flags, fd, offset)
                let addr = ctx.get_x(0);
                let len = ctx.get_x(1) as usize;
                let prot_raw = ctx.get_x(2) as i32;
                let prot = nix::sys::mman::ProtFlags::from_bits_truncate(prot_raw);

                let target_addr = if addr == 0 {
                    let map_addr = mem.brk_current;
                    let page_size = 4096u64;
                    let aligned_len = ((len as u64 + page_size - 1) / page_size) * page_size;
                    mem.brk_current += aligned_len;
                    map_addr
                } else {
                    addr
                };

                let mapped_addr = mem.map_anonymous_prot(target_addr, len, prot)?;
                ctx.set_x(0, mapped_addr);
                Ok(mapped_addr as i64)
            }
            226 => {
                // sys_mprotect(addr, len, prot)
                let addr = ctx.get_x(0);
                let len = ctx.get_x(1) as usize;
                let prot_raw = ctx.get_x(2) as i32;
                let prot = nix::sys::mman::ProtFlags::from_bits_truncate(prot_raw);

                mem.mprotect(addr, len, prot)?;
                ctx.set_x(0, 0);
                Ok(0)
            }
            278 => {
                // sys_getrandom(buf, buflen, flags)
                let buf_ptr = ctx.get_x(0);
                let buflen = ctx.get_x(1) as usize;
                let dummy_rand = vec![0x42u8; buflen];
                mem.write(buf_ptr, &dummy_rand)?;
                let res = buflen as i64;
                ctx.set_x(0, res as u64);
                Ok(res)
            }
            _ => Err(crate::Error::UnhandledSyscall(nr)),
        }
    }
}
