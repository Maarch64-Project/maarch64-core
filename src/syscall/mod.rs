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

pub struct SyscallDispatcher;

impl SyscallDispatcher {
    pub fn handle_syscall(ctx: &mut CpuContext, mem: &mut MemoryManager) -> Result<i64> {
        let nr = ctx.get_x(8); // ARM64 syscall number is in X8
        tracing::info!("Syscall {} (X0={:#x}, X1={:#x}, X2={:#x})", nr, ctx.get_x(0), ctx.get_x(1), ctx.get_x(2));
        match nr {
            43 | 44 => {
                // sys_statfs / sys_fstatfs
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
                // sys_socket(domain, type, protocol)
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
            203 => {
                // sys_connect(sockfd, addr, addrlen)
                let sockfd = ctx.get_x(0) as i32;
                let addr_ptr = ctx.get_x(1);
                let addrlen = ctx.get_x(2) as usize;
                if addr_ptr != 0 && addrlen > 0 {
                    let addr_bytes = mem.read(addr_ptr, addrlen)?;
                    let ret = unsafe { libc::connect(sockfd, addr_bytes.as_ptr() as *const libc::sockaddr, addrlen as u32) };
                    if ret < 0 {
                        let err = unsafe { *libc::__errno_location() };
                        let neg_err = -err as i64;
                        ctx.set_x(0, neg_err as u64);
                        Ok(neg_err)
                    } else {
                        ctx.set_x(0, 0);
                        Ok(0)
                    }
                } else {
                    ctx.set_x(0, 0);
                    Ok(0)
                }
            }
            48 => {
                // sys_faccessat(dirfd, pathname, mode, flags)
                let dirfd = ctx.get_x(0) as i32;
                let path_ptr = ctx.get_x(1);
                let mode = ctx.get_x(2) as i32;
                let flags = ctx.get_x(3) as i32;

                let path_bytes = mem.read_string(path_ptr)?;
                let c_path = std::ffi::CString::new(path_bytes).map_err(|_| crate::Error::MemoryError("invalid path".into()))?;

                let ret = unsafe { libc::faccessat(dirfd, c_path.as_ptr(), mode, flags) };
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
                // sys_openat(dfd, filename, flags, mode)
                let dfd = ctx.get_x(0) as i32;
                let path_ptr = ctx.get_x(1);
                let flags = ctx.get_x(2) as i32;
                let mode = ctx.get_x(3) as u32;

                let path_bytes = mem.read_string(path_ptr)?;
                let c_path = std::ffi::CString::new(path_bytes)
                    .map_err(|e| crate::Error::LoadError(e.to_string()))?;

                let host_flags = translate_open_flags(flags);
                tracing::info!("[sys_openat] dfd={} path={:?} flags=0x{:x} -> host_flags=0x{:x}", dfd, c_path, flags, host_flags);

                let path_str = c_path.to_string_lossy();
                let actual_path = if crate::vfs::Vfs::is_passwd_path(&path_str) {
                    let tmp_path = crate::vfs::Vfs::prepare_mock_passwd_file();
                    std::ffi::CString::new(tmp_path.to_str().unwrap()).unwrap()
                } else {
                    c_path
                };

                let res = unsafe {
                    libc::openat(dfd, actual_path.as_ptr(), host_flags, mode)
                };
                if res >= 0 {
                    let cur_off = unsafe { libc::lseek(res, 0, libc::SEEK_CUR) };
                    tracing::info!("[sys_openat] opened fd={}, initial_offset={}", res, cur_off);
                }
                let ret = if res < 0 {
                    let err = unsafe { *libc::__errno_location() };
                    -err as i64
                } else {
                    res as i64
                };
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
            67 => {
                // sys_pread64(fd, buf, count, offset)
                let fd = ctx.get_x(0) as i32;
                let buf_ptr = ctx.get_x(1);
                let count = ctx.get_x(2) as usize;
                let offset = ctx.get_x(3) as i64;
                let mut host_buf = vec![0u8; count];
                let ret = unsafe { libc::pread(fd, host_buf.as_mut_ptr() as *mut libc::c_void, count, offset) };
                if ret < 0 {
                    let err = unsafe { *libc::__errno_location() };
                    let neg_err = -err as i64;
                    ctx.set_x(0, neg_err as u64);
                    Ok(neg_err)
                } else {
                    mem.write(buf_ptr, &host_buf[..ret as usize])?;
                    ctx.set_x(0, ret as u64);
                    Ok(ret as i64)
                }
            }
            68 => {
                // sys_pwrite64(fd, buf, count, offset)
                let fd = ctx.get_x(0) as i32;
                let buf_ptr = ctx.get_x(1);
                let count = ctx.get_x(2) as usize;
                let offset = ctx.get_x(3) as i64;
                let host_buf = mem.read(buf_ptr, count)?;
                let ret = unsafe { libc::pwrite(fd, host_buf.as_ptr() as *const libc::c_void, count, offset) };
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

            93 | 94 => {
                // sys_exit / sys_exit_group(status)
                let status = ctx.get_x(0) as i32;
                tracing::debug!("[sys_exit] status = {}, pc = {:#x}", status, ctx.pc);
                unsafe { libc::fflush(std::ptr::null_mut()); }
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
            115 => {
                // sys_gettimeofday(tv, tz)
                let tv_ptr = ctx.get_x(0);
                if tv_ptr != 0 {
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
                    let sec = now.as_secs() as i64;
                    let usec = now.subsec_micros() as i64;
                    let mut buf = [0u8; 16];
                    buf[0..8].copy_from_slice(&sec.to_le_bytes());
                    buf[8..16].copy_from_slice(&usec.to_le_bytes());
                    mem.write(tv_ptr, &buf)?;
                }
                ctx.set_x(0, 0);
                Ok(0)
            }
            99 => {
                // sys_set_robust_list(head, len)
                ctx.set_x(0, 0);
                Ok(0)
            }
            150 | 151 | 152 | 153 | 154 | 155 | 156 | 157 | 158 | 159 => {
                // sys_setfsuid (150), sys_setfsgid (151), sys_times (152), etc.
                ctx.set_x(0, 0);
                Ok(0)
            }
            293 => {
                // sys_rseq (Restartable Sequences) - return -ENOSYS (-38)
                let ret = -38i64;
                ctx.set_x(0, ret as u64);
                Ok(ret)
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
            17 => {
                // sys_getcwd(buf, size)
                let buf_ptr = ctx.get_x(0);
                let size = ctx.get_x(1) as usize;
                if let Ok(cwd) = std::env::current_dir() {
                    let cwd_str = cwd.to_string_lossy();
                    let bytes = cwd_str.as_bytes();
                    if size > 0 && bytes.len() + 1 > size {
                        ctx.set_x(0, (-34i64) as u64); // ERANGE
                        Ok(-34)
                    } else {
                        mem.write(buf_ptr, bytes)?;
                        mem.write(buf_ptr + bytes.len() as u64, &[0u8])?;
                        let ret_len = (bytes.len() + 1) as u64;
                        ctx.set_x(0, ret_len);
                        Ok(ret_len as i64)
                    }
                } else {
                    ctx.set_x(0, (-2i64) as u64); // ENOENT
                    Ok(-2)
                }
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
                    let map_addr = mem.mmap_current;
                    let page_size = 4096u64;
                    let aligned_len = ((len as u64 + page_size - 1) / page_size) * page_size;
                    mem.mmap_current += aligned_len;
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
                let dummy_rand = vec![0u8; buflen];
                mem.write(buf_ptr, &dummy_rand)?;
                let res = buflen as i64;
                ctx.set_x(0, res as u64);
                Ok(res)
            }
            66 => {
                // sys_writev(fd, iov, iovcnt)
                let fd = ctx.get_x(0) as i32;
                let iov_ptr = ctx.get_x(1);
                let iovcnt = ctx.get_x(2) as usize;

                let mut total_written = 0i64;
                for i in 0..iovcnt {
                    let entry_ptr = iov_ptr + (i * 16) as u64;
                    let base_bytes = mem.read(entry_ptr, 8)?;
                    let len_bytes = mem.read(entry_ptr + 8, 8)?;
                    let base = u64::from_le_bytes(base_bytes.try_into().unwrap());
                    let len = u64::from_le_bytes(len_bytes.try_into().unwrap()) as usize;

                    if len > 0 {
                        let buf = mem.read(base, len)?;
                        tracing::debug!("[writev] fd={}, str={:?}", fd, String::from_utf8_lossy(&buf));
                        let ret = unsafe {
                            libc::write(fd, buf.as_ptr() as *const std::ffi::c_void, len)
                        };
                        if ret > 0 {
                            total_written += ret as i64;
                        }
                    }
                }
                ctx.set_x(0, total_written as u64);
                Ok(total_written)
            }
            129 | 134 | 135 => {
                // sys_kill / sys_rt_sigaction / sys_rt_sigprocmask
                ctx.set_x(0, 0);
                Ok(0)
            }
            131 => {
                // sys_tgkill
                let code = ctx.get_x(2) as i32;
                std::process::exit(code);
            }
            144 | 145 | 146 | 148 => {
                // sys_setreuid, sys_setregid, sys_setresuid, sys_setresgid
                ctx.set_x(0, 0);
                Ok(0)
            }
            147 | 149 => {
                // sys_getresuid(ruid*, euid*, suid*), sys_getresgid(rgid*, egid*, sgid*)
                let rptr = ctx.get_x(0);
                let eptr = ctx.get_x(1);
                let sptr = ctx.get_x(2);
                let id = if nr == 147 { unsafe { libc::geteuid() } } else { unsafe { libc::getegid() } };
                let bytes = id.to_le_bytes();
                if rptr != 0 { let _ = mem.write(rptr, &bytes); }
                if eptr != 0 { let _ = mem.write(eptr, &bytes); }
                if sptr != 0 { let _ = mem.write(sptr, &bytes); }
                ctx.set_x(0, 0);
                Ok(0)
            }
            172 | 173 | 174 | 175 | 176 | 177 => {
                // sys_getpid, sys_getppid, sys_getuid, sys_geteuid, sys_getgid, sys_getegid
                let id = match nr {
                    172 => unsafe { libc::getpid() as i64 },
                    173 => unsafe { libc::getppid() as i64 },
                    174 => unsafe { libc::getuid() as i64 },
                    175 => unsafe { libc::geteuid() as i64 },
                    176 => unsafe { libc::getgid() as i64 },
                    177 => unsafe { libc::getegid() as i64 },
                    _ => 1000i64,
                };
                ctx.set_x(0, id as u64);
                Ok(id)
            }
            98 => {
                // sys_futex(uaddr, futex_op, val, timeout, uaddr2, val3)
                let uaddr = ctx.get_x(0);
                let op = ctx.get_x(1) as i32 & 0x7f; // FUTEX_CMD_MASK
                if op == 0 { // FUTEX_WAIT
                    let val = ctx.get_x(2) as u32;
                    let cur_val = mem.read(uaddr, 4).ok().map(|b| u32::from_le_bytes(b.try_into().unwrap())).unwrap_or(0);
                    if cur_val != val {
                        let err = -11i64; // -EAGAIN
                        ctx.set_x(0, err as u64);
                        Ok(err)
                    } else {
                        ctx.set_x(0, 0);
                        Ok(0)
                    }
                } else { // FUTEX_WAKE / other
                    ctx.set_x(0, 0);
                    Ok(0)
                }
            }
            78 => {
                // sys_readlinkat(dirfd, pathname, buf, bufsz)
                let path_ptr = ctx.get_x(1);
                let buf_ptr = ctx.get_x(2);
                let bufsz = ctx.get_x(3) as usize;

                let path_bytes = mem.read_string(path_ptr)?;
                let path_str = String::from_utf8_lossy(&path_bytes);
                tracing::debug!("[readlinkat] path = {:?}", path_str);

                let target = if path_str == "/proc/self/exe" {
                    "/home/fukayatti0/Maarch64-Project/tests/bin/busybox".to_string()
                } else if path_str == "/proc/self/cwd" {
                    std::env::current_dir().map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|_| "/".to_string())
                } else if let Ok(link_target) = std::fs::read_link(&*path_str) {
                    link_target.to_string_lossy().to_string()
                } else {
                    "".to_string()
                };

                if target.is_empty() {
                    let err = -22i64; // -EINVAL (not a symbolic link)
                    ctx.set_x(0, err as u64);
                    Ok(err)
                } else {
                    let bytes = target.as_bytes();
                    let len = bytes.len().min(bufsz);
                    mem.write(buf_ptr, &bytes[..len])?;
                    ctx.set_x(0, len as u64);
                    Ok(len as i64)
                }
            }
            64 => {
                // sys_write(fd, buf, count)
                let fd = ctx.get_x(0) as i32;
                let buf_ptr = ctx.get_x(1);
                let count = ctx.get_x(2) as usize;
                if count > 0 {
                    let data = mem.read(buf_ptr, count)?;
                    tracing::info!("[sys_write] fd={} count={} text={:?}", fd, count, String::from_utf8_lossy(&data));
                    let ret = unsafe {
                        libc::write(fd, data.as_ptr() as *const libc::c_void, count)
                    };
                    if ret < 0 {
                        let err = unsafe { *libc::__errno_location() };
                        ctx.set_x(0, (-err as i64) as u64);
                        Ok(-err as i64)
                    } else {
                        ctx.set_x(0, ret as u64);
                        Ok(ret as i64)
                    }
                } else {
                    ctx.set_x(0, 0);
                    Ok(0)
                }
            }

            167 => {
                // sys_prctl(option, ...)
                let option = ctx.get_x(0);
                let arg2 = ctx.get_x(1);
                tracing::debug!("sys_prctl(option = {:#x}, arg2 = {:#x})", option, arg2);
                match option {
                    15 => {
                        // PR_SET_NAME
                        ctx.set_x(0, 0);
                        Ok(0)
                    }
                    _ => {
                        ctx.set_x(0, 0);
                        Ok(0)
                    }
                }
            }

            79 | 80 => {
                // sys_newfstatat(79), sys_fstat(80)
                let statbuf = if nr == 79 { ctx.get_x(2) } else { ctx.get_x(1) };
                if statbuf != 0 {
                    let meta_res = if nr == 80 {
                        let fd = ctx.get_x(0) as i32;
                        use std::os::unix::io::FromRawFd;
                        let file = unsafe { std::fs::File::from_raw_fd(fd) };
                        let res = file.metadata();
                        let _ = std::mem::forget(file);
                        res
                    } else {
                        let path = mem.read_string(ctx.get_x(1)).map(|b| String::from_utf8_lossy(&b).to_string()).unwrap_or_default();
                        let target_path = if path.is_empty() { ".".to_string() } else { path };
                        std::fs::metadata(&target_path)
                    };
                    if let Ok(meta) = meta_res {
                        tracing::info!("[sys_fstat/newfstatat] nr={} size={} mode={:#o} statbuf={:#x}", nr, meta.size(), meta.mode(), statbuf);
                        use std::os::unix::fs::MetadataExt;
                        let mut buf = [0u8; 128];
                        buf[0..8].copy_from_slice(&meta.dev().to_le_bytes());
                        buf[8..16].copy_from_slice(&meta.ino().to_le_bytes());
                        buf[16..20].copy_from_slice(&meta.mode().to_le_bytes());
                        buf[20..24].copy_from_slice(&(meta.nlink() as u32).to_le_bytes());
                        buf[24..28].copy_from_slice(&meta.uid().to_le_bytes());
                        buf[28..32].copy_from_slice(&meta.gid().to_le_bytes());
                        buf[32..40].copy_from_slice(&meta.rdev().to_le_bytes());
                        buf[48..56].copy_from_slice(&(meta.size() as i64).to_le_bytes());
                        buf[56..60].copy_from_slice(&(meta.blksize() as u32).to_le_bytes());
                        buf[64..72].copy_from_slice(&(meta.blocks() as i64).to_le_bytes());
                        let _ = mem.write(statbuf, &buf);
                        ctx.set_x(0, 0);
                        Ok(0)
                    } else {
                        let err = -2i64; // -ENOENT
                        ctx.set_x(0, err as u64);
                        Ok(err)
                    }
                } else {
                    ctx.set_x(0, 0);
                    Ok(0)
                }
            }
            23 | 24 => {
                // sys_dup3(23), sys_dup(24)
                let oldfd = ctx.get_x(0) as i32;
                let newfd = unsafe { libc::dup(oldfd) };
                let res = if newfd >= 0 { newfd as i64 } else { -1i64 };
                ctx.set_x(0, res as u64);
                Ok(res)
            }
            29 => {
                // sys_ioctl(fd, request, argp)
                let req = ctx.get_x(1);
                let argp = ctx.get_x(2);
                if (req & 0xffff) == 0x5413 || (req & 0xffff) == 0x542a {
                    // TIOCGWINSZ
                    if argp != 0 {
                        let winsz: [u8; 8] = [24, 0, 80, 0, 0, 0, 0, 0];
                        let _ = mem.write(argp, &winsz);
                    }
                }
                ctx.set_x(0, 0);
                Ok(0)
            }
            25 | 233 | 261 => {
                // sys_fcntl(25), sys_madvise(233), sys_prlimit64(261)
                ctx.set_x(0, 0);
                Ok(0)
            }
            61 => {
                // sys_getdents64(fd, dirp, count)
                let fd = ctx.get_x(0) as i32;
                let dirp_ptr = ctx.get_x(1);
                let count = ctx.get_x(2) as usize;

                let mut tmp_buf = vec![0u8; count];
                let ret = unsafe {
                    libc::syscall(libc::SYS_getdents64, fd, tmp_buf.as_mut_ptr(), count)
                };
                if ret > 0 {
                    mem.write(dirp_ptr, &tmp_buf[..ret as usize])?;
                    ctx.set_x(0, ret as u64);
                    Ok(ret as i64)
                } else if ret < 0 {
                    let err = unsafe { *libc::__errno_location() };
                    let neg_err = -err as i64;
                    ctx.set_x(0, neg_err as u64);
                    Ok(neg_err)
                } else {
                    ctx.set_x(0, 0);
                    Ok(0)
                }
            }
            62 => {
                // sys_lseek(fd, offset, whence)
                let fd = ctx.get_x(0) as i32;
                let offset = ctx.get_x(1) as i64;
                let whence = ctx.get_x(2) as i32;

                let ret = unsafe { libc::lseek(fd, offset, whence) };
                tracing::info!("[sys_lseek] fd={}, offset={}, whence={} -> ret={}", fd, offset, whence, ret);
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
            71 => {
                // sys_sendfile(out_fd, in_fd, offset_ptr, count)
                let out_fd = ctx.get_x(0) as i32;
                let in_fd = ctx.get_x(1) as i32;
                let offset_ptr = ctx.get_x(2);
                let count = ctx.get_x(3) as usize;

                let mut off: i64 = 0;
                let has_off = offset_ptr != 0;
                if has_off {
                    let off_bytes = mem.read(offset_ptr, 8)?;
                    off = i64::from_le_bytes(off_bytes.try_into().unwrap());
                }

                let ret = unsafe {
                    libc::sendfile(
                        out_fd,
                        in_fd,
                        if has_off { &mut off as *mut i64 } else { std::ptr::null_mut() },
                        count,
                    )
                };

                if ret < 0 {
                    let err = unsafe { *libc::__errno_location() };
                    let neg_err = -err as i64;
                    ctx.set_x(0, neg_err as u64);
                    Ok(neg_err)
                } else {
                    if has_off {
                        mem.write(offset_ptr, &off.to_le_bytes())?;
                    }
                    ctx.set_x(0, ret as u64);
                    Ok(ret as i64)
                }
            }
            179 => {
                // sys_sysinfo(info)
                let info_ptr = ctx.get_x(0);
                if info_ptr != 0 {
                    // struct sysinfo: 112 bytes
                    let mut info = [0u8; 112];
                    // uptime (i64 at offset 0)
                    info[0..8].copy_from_slice(&3600i64.to_le_bytes());
                    // loads (3 * u64 at offset 8)
                    info[8..16].copy_from_slice(&1000u64.to_le_bytes());
                    // totalram (u64 at offset 32)
                    info[32..40].copy_from_slice(&(8192u64 * 1024 * 1024).to_le_bytes());
                    // freeram (u64 at offset 40)
                    info[40..48].copy_from_slice(&(4096u64 * 1024 * 1024).to_le_bytes());
                    // procs (u16 at offset 80)
                    info[80..82].copy_from_slice(&100u16.to_le_bytes());
                    // mem_unit (u32 at offset 84)
                    info[84..88].copy_from_slice(&1u32.to_le_bytes());

                    mem.write(info_ptr, &info)?;
                }
                ctx.set_x(0, 0);
                Ok(0)
            }
            _ => Err(crate::Error::UnhandledSyscall(nr)),
        }
    }
}
