use crate::{cpu::CpuContext, memory::MemoryManager, Result};

pub struct DarwinSyscall;

impl DarwinSyscall {
    pub fn handle(nr: u64, ctx: &mut CpuContext, mem: &mut MemoryManager) -> Result<i64> {
        let bsd_nr = nr & 0x00FF_FFFF;
        tracing::info!("[Darwin Syscall/Mach Trap] nr={:#x} (bsd_nr={})", nr, bsd_nr);

        match bsd_nr {
            1 => {
                // sys_exit
                let code = ctx.get_x(0) as i32;
                ctx.exited = true;
                ctx.exit_code = code;
                Ok(code as i64)
            }
            4 => {
                // sys_write
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
            199 => {
                // sys_mmap
                let addr = ctx.get_x(0);
                let len = ctx.get_x(1) as usize;
                let target_addr = if addr == 0 { 0x7f030000 } else { addr };
                mem.map_anonymous(target_addr, len)?;
                ctx.set_x(0, target_addr);
                Ok(target_addr as i64)
            }
            _ => {
                tracing::warn!("[Darwin Syscall] Unhandled syscall nr={:#x} (bsd_nr={})", nr, bsd_nr);
                ctx.set_x(0, 0);
                Ok(0)
            }
        }
    }
}
