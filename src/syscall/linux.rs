use crate::{cpu::CpuContext, memory::MemoryManager, Result};

pub fn translate_open_flags(aarch64_flags: i32) -> i32 {
    let mut host_flags = 0;
    let common_mask = libc::O_ACCMODE | libc::O_CREAT | libc::O_EXCL | libc::O_NOCTTY | libc::O_TRUNC | libc::O_APPEND | libc::O_NONBLOCK | libc::O_CLOEXEC;
    host_flags |= aarch64_flags & common_mask;

    if aarch64_flags & 0x4000 != 0 {
        host_flags |= libc::O_DIRECTORY;
    }
    if aarch64_flags & 0x8000 != 0 {
        host_flags |= libc::O_NOFOLLOW;
    }
    if aarch64_flags & 0x10000 != 0 {
        host_flags |= libc::O_DIRECT;
    }
    if aarch64_flags & 0x40000 != 0 {
        host_flags |= libc::O_NOATIME;
    }
    if aarch64_flags & 0x400000 != 0 {
        host_flags |= libc::O_PATH;
    }
    host_flags
}

pub struct LinuxSyscall;

impl LinuxSyscall {
    pub fn handle(ctx: &mut CpuContext, mem: &mut MemoryManager) -> Result<i64> {
        let nr = ctx.get_x(8);
        tracing::info!("Linux Syscall {} (X0={:#x}, X1={:#x}, X2={:#x})", nr, ctx.get_x(0), ctx.get_x(1), ctx.get_x(2));
        match nr {
            43 | 44 => {
                let buf_ptr = ctx.get_x(1);
                if buf_ptr != 0 {
                    let mut buf = [0u8; 120];
                    buf[0..8].copy_from_slice(&0xef53i64.to_le_bytes());
                    buf[8..16].copy_from_slice(&4096i64.to_le_bytes());
                    buf[16..24].copy_from_slice(&1000000i64.to_le_bytes());
                    buf[24..32].copy_from_slice(&500000i64.to_le_bytes());
                    buf[32..40].copy_from_slice(&500000i64.to_le_bytes());
                    mem.write(buf_ptr, &buf)?;
                }
                ctx.set_x(0, 0);
                Ok(0)
            }
            198 => {
                let domain = ctx.get_x(0) as i32;
                let type_ = ctx.get_x(1) as i32;
                let protocol = ctx.get_x(2) as i32;
                let ret = unsafe { libc::socket(domain, type_, protocol) };
                if ret < 0 {
                    let err = unsafe { *libc::__errno_location() };
                    let neg_err = -err as i64;
                    ctx.set_x(0, neg_err as u64);
                    Ok(neg_err)
                } else {
                    ctx.set_x(0, ret as u64);
                    Ok(ret as i64)
                }
            }
            199 => {
                let sockfd = ctx.get_x(0) as i32;
                let addr_ptr = ctx.get_x(1);
                let addrlen_ptr = ctx.get_x(2);
                let mut host_addr = [0u8; 128];
                let mut host_len = 128u32;
                let ret = unsafe {
                    libc::getsockname(
                        sockfd,
                        host_addr.as_mut_ptr() as *mut libc::sockaddr,
                        &mut host_len as *mut libc::socklen_t,
                    )
                };
                if ret < 0 {
                    let err = unsafe { *libc::__errno_location() };
                    let neg_err = -err as i64;
                    ctx.set_x(0, neg_err as u64);
                    Ok(neg_err)
                } else {
                    if addr_ptr != 0 && addrlen_ptr != 0 {
                        let _ = mem.write(addr_ptr, &host_addr[..host_len as usize]);
                        let _ = mem.write(addrlen_ptr, &host_len.to_le_bytes());
                    }
                    ctx.set_x(0, 0);
                    Ok(0)
                }
            }
            200 => {
                let sockfd = ctx.get_x(0) as i32;
                let addr_ptr = ctx.get_x(1);
                let addrlen_ptr = ctx.get_x(2);
                let mut host_addr = [0u8; 128];
                let mut host_len = 128u32;
                let ret = unsafe {
                    libc::getpeername(
                        sockfd,
                        host_addr.as_mut_ptr() as *mut libc::sockaddr,
                        &mut host_len as *mut libc::socklen_t,
                    )
                };
                if ret < 0 {
                    let err = unsafe { *libc::__errno_location() };
                    let neg_err = -err as i64;
                    ctx.set_x(0, neg_err as u64);
                    Ok(neg_err)
                } else {
                    if addr_ptr != 0 && addrlen_ptr != 0 {
                        let _ = mem.write(addr_ptr, &host_addr[..host_len as usize]);
                        let _ = mem.write(addrlen_ptr, &host_len.to_le_bytes());
                    }
                    ctx.set_x(0, 0);
                    Ok(0)
                }
            }
            203 => {
                let sockfd = ctx.get_x(0) as i32;
                let backlog = ctx.get_x(1) as i32;
                let ret = unsafe { libc::listen(sockfd, backlog) };
                if ret < 0 {
                    let err = unsafe { *libc::__errno_location() };
                    let neg_err = -err as i64;
                    ctx.set_x(0, neg_err as u64);
                    Ok(neg_err)
                } else {
                    ctx.set_x(0, 0);
                    Ok(0)
                }
            }
            208 => {
                let sockfd = ctx.get_x(0) as i32;
                let level = ctx.get_x(1) as i32;
                let optname = ctx.get_x(2) as i32;
                let optval_ptr = ctx.get_x(3);
                let optlen = ctx.get_x(4) as u32;

                let mut optval_buf = vec![0u8; optlen as usize];
                if optval_ptr != 0 && optlen > 0 {
                    if let Ok(bytes) = mem.read(optval_ptr, optlen as usize) {
                        optval_buf[..bytes.len()].copy_from_slice(&bytes);
                    }
                }

                let ret = unsafe {
                    libc::setsockopt(
                        sockfd,
                        level,
                        optname,
                        optval_buf.as_ptr() as *const libc::c_void,
                        optlen as libc::socklen_t,
                    )
                };

                if ret < 0 {
                    let err = unsafe { *libc::__errno_location() };
                    let neg_err = -err as i64;
                    ctx.set_x(0, neg_err as u64);
                    Ok(neg_err)
                } else {
                    ctx.set_x(0, 0);
                    Ok(0)
                }
            }
            209 => {
                let sockfd = ctx.get_x(0) as i32;
                let level = ctx.get_x(1) as i32;
                let optname = ctx.get_x(2) as i32;
                let optval_ptr = ctx.get_x(3);
                let optlen_ptr = ctx.get_x(4);

                let mut optval_buf = [0u8; 256];
                let mut optlen: u32 = 256;

                let ret = unsafe {
                    libc::getsockopt(
                        sockfd,
                        level,
                        optname,
                        optval_buf.as_mut_ptr() as *mut libc::c_void,
                        &mut optlen as *mut libc::socklen_t,
                    )
                };

                if ret < 0 {
                    let err = unsafe { *libc::__errno_location() };
                    let neg_err = -err as i64;
                    ctx.set_x(0, neg_err as u64);
                    Ok(neg_err)
                } else {
                    if optval_ptr != 0 && optlen_ptr != 0 {
                        let _ = mem.write(optval_ptr, &optval_buf[..optlen as usize]);
                        let _ = mem.write(optlen_ptr, &optlen.to_le_bytes());
                    }
                    ctx.set_x(0, 0);
                    Ok(0)
                }
            }
            17 => {
                let _dfd = ctx.get_x(0) as i32;
                let target_ptr = ctx.get_x(1);
                let linkpath_ptr = ctx.get_x(2);
                let target_path = if target_ptr != 0 {
                    String::from_utf8_lossy(&mem.read_string(target_ptr)?).to_string()
                } else {
                    String::new()
                };
                let link_path = if linkpath_ptr != 0 {
                    String::from_utf8_lossy(&mem.read_string(linkpath_ptr)?).to_string()
                } else {
                    String::new()
                };

                let target_c = std::ffi::CString::new(target_path).map_err(|e| crate::Error::LoadError(format!("CString error: {}", e)))?;
                let link_c = std::ffi::CString::new(link_path).map_err(|e| crate::Error::LoadError(format!("CString error: {}", e)))?;

                let ret = unsafe { libc::symlink(target_c.as_ptr(), link_c.as_ptr()) };
                if ret < 0 {
                    let err = unsafe { *libc::__errno_location() };
                    let neg_err = -err as i64;
                    ctx.set_x(0, neg_err as u64);
                    Ok(neg_err)
                } else {
                    ctx.set_x(0, 0);
                    Ok(0)
                }
            }
            78 => {
                let pid = ctx.get_x(0) as i32;
                let sig = ctx.get_x(1) as i32;
                let ret = unsafe { libc::kill(pid, sig) };
                if ret < 0 {
                    let err = unsafe { *libc::__errno_location() };
                    let neg_err = -err as i64;
                    ctx.set_x(0, neg_err as u64);
                    Ok(neg_err)
                } else {
                    ctx.set_x(0, 0);
                    Ok(0)
                }
            }
            56 => {
                let flags = ctx.get_x(0) as u64;
                let stack_ptr = ctx.get_x(1);
                let ptid_ptr = ctx.get_x(2);
                let tls_ptr = ctx.get_x(3);
                let ctid_ptr = ctx.get_x(4);
                tracing::info!("[Syscall clone] flags={:#x}, stack={:#x}, tls={:#x}", flags, stack_ptr, tls_ptr);
                
                let is_thread = (flags & 0x00010000) != 0; // CLONE_THREAD
                if is_thread {
                    let mut child_ctx = ctx.clone();
                    if stack_ptr != 0 {
                        child_ctx.sp = stack_ptr;
                    }
                    if tls_ptr != 0 {
                        child_ctx.tpidr_el0 = tls_ptr;
                    }
                    child_ctx.set_x(0, 0);

                    let child_tid = (std::process::id() + 1) as u64;
                    if ctid_ptr != 0 {
                        let _ = mem.write(ctid_ptr, &(child_tid as u32).to_le_bytes());
                    }
                    if ptid_ptr != 0 {
                        let _ = mem.write(ptid_ptr, &(child_tid as u32).to_le_bytes());
                    }

                    ctx.set_x(0, child_tid);
                    Ok(child_tid as i64)
                } else {
                    let child_pid = (std::process::id() + 1) as i64;
                    ctx.set_x(0, child_pid as u64);
                    Ok(child_pid)
                }
            }
            98 => {
                let uaddr = ctx.get_x(0);
                let futex_op = ctx.get_x(1) as i32 & 0x7f;
                let val = ctx.get_x(2) as u32;
                tracing::info!("[Syscall futex] uaddr={:#x}, op={}, val={}", uaddr, futex_op, val);
                match futex_op {
                    0 => {
                        if uaddr != 0 {
                            if let Ok(data) = mem.read(uaddr, 4) {
                                let cur_val = u32::from_le_bytes(data.try_into().unwrap());
                                if cur_val != val {
                                    ctx.set_x(0, (-11i64) as u64);
                                    return Ok(-11);
                                }
                            }
                        }
                        ctx.set_x(0, 0);
                        Ok(0)
                    }
                    1 => {
                        ctx.set_x(0, val as u64);
                        Ok(val as i64)
                    }
                    _ => {
                        ctx.set_x(0, 0);
                        Ok(0)
                    }
                }
            }
            99 => {
                let head_ptr = ctx.get_x(0);
                let len = ctx.get_x(1);
                tracing::info!("[Syscall set_robust_list] head={:#x}, len={}", head_ptr, len);
                ctx.set_x(0, 0);
                Ok(0)
            }
            63 => {
                let fd = ctx.get_x(0) as i32;
                let cmd = ctx.get_x(1) as i32;
                let arg = ctx.get_x(2);
                let ret = unsafe { libc::fcntl(fd, cmd, arg) };
                if ret < 0 {
                    let err = unsafe { *libc::__errno_location() };
                    let neg_err = -err as i64;
                    ctx.set_x(0, neg_err as u64);
                    Ok(neg_err)
                } else {
                    ctx.set_x(0, ret as u64);
                    Ok(ret as i64)
                }
            }
            160 => {
                let pid = ctx.get_x(0) as i32;
                let ret = unsafe { libc::uname(std::ptr::null_mut()) };
                ctx.set_x(0, 0);
                Ok(0)
            }
            172 => {
                let pid = (std::process::id()) as u64;
                ctx.set_x(0, pid);
                Ok(pid as i64)
            }
            174 => {
                let ppid = (unsafe { libc::getppid() }) as u64;
                ctx.set_x(0, ppid);
                Ok(ppid as i64)
            }
            175 => {
                let uid = (unsafe { libc::getuid() }) as u64;
                ctx.set_x(0, uid);
                Ok(uid as i64)
            }
            176 => {
                let euid = (unsafe { libc::geteuid() }) as u64;
                ctx.set_x(0, euid);
                Ok(euid as i64)
            }
            177 => {
                let gid = (unsafe { libc::getgid() }) as u64;
                ctx.set_x(0, gid);
                Ok(gid as i64)
            }
            178 => {
                let egid = (unsafe { libc::getegid() }) as u64;
                ctx.set_x(0, egid);
                Ok(egid as i64)
            }
            93 => {
                let code = ctx.get_x(0) as i32;
                ctx.exited = true;
                ctx.exit_code = code;
                Ok(code as i64)
            }
            94 => {
                let code = ctx.get_x(0) as i32;
                ctx.exited = true;
                ctx.exit_code = code;
                Ok(code as i64)
            }
            64 => {
                let fd = ctx.get_x(0);
                let buf_ptr = ctx.get_x(1);
                let count = ctx.get_x(2) as usize;
                if let Ok(data) = mem.read(buf_ptr, count) {
                    if fd == 1 || fd == 2 {
                        let msg = String::from_utf8_lossy(&data);
                        print!("{}", msg);
                    }
                }
                ctx.set_x(0, count as u64);
                Ok(count as i64)
            }
            62 => {
                let fd = ctx.get_x(0) as i32;
                let ret = unsafe { libc::close(fd) };
                if ret < 0 {
                    let err = unsafe { *libc::__errno_location() };
                    let neg_err = -err as i64;
                    ctx.set_x(0, neg_err as u64);
                    Ok(neg_err)
                } else {
                    ctx.set_x(0, 0);
                    Ok(0)
                }
            }
            57 => {
                let filename_ptr = ctx.get_x(0);
                let argv_ptr = ctx.get_x(1);
                let envp_ptr = ctx.get_x(2);
                let filename = if filename_ptr != 0 {
                    String::from_utf8_lossy(&mem.read_string(filename_ptr)?).to_string()
                } else {
                    String::new()
                };
                tracing::info!("[Syscall execve] filename={:?}", filename);
                ctx.set_x(0, (-2i64) as u64);
                Ok(-2)
            }
            222 => {
                let addr = ctx.get_x(0);
                let len = ctx.get_x(1) as usize;
                let prot = ctx.get_x(2) as u32;
                let flags = ctx.get_x(3) as u32;
                let fd = ctx.get_x(4) as i32;
                let offset = ctx.get_x(5) as u64;

                let target_addr = if addr == 0 { 0x7f030000 } else { addr };
                mem.map_anonymous(target_addr, len)?;
                ctx.set_x(0, target_addr);
                Ok(target_addr as i64)
            }
            214 => {
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
                ctx.set_x(0, 0);
                Ok(0)
            }
            226 => {
                ctx.set_x(0, 0);
                Ok(0)
            }
            169 => {
                let tp = ctx.get_x(0);
                ctx.tpidr_el0 = tp;
                ctx.set_x(0, 0);
                Ok(0)
            }
            96 => {
                let tid_ptr = ctx.get_x(0);
                if tid_ptr != 0 {
                    let _ = mem.write(tid_ptr, &0u32.to_le_bytes());
                }
                ctx.exited = true;
                ctx.exit_code = 0;
                Ok(0)
            }
            _ => {
                tracing::warn!("Unhandled Linux Syscall nr={}", nr);
                ctx.set_x(0, 0);
                Ok(0)
            }
        }
    }
}
