use crate::{cpu::CpuContext, memory::MemoryManager, Result};

pub struct SyscallDispatcher;

impl SyscallDispatcher {
    pub fn handle_syscall(ctx: &mut CpuContext, mem: &MemoryManager) -> Result<i64> {
        let nr = ctx.get_x(8); // ARM64 syscall number is in X8
        match nr {
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
                std::process::exit(status);
            }
            _ => Err(crate::Error::UnhandledSyscall(nr)),
        }
    }
}
