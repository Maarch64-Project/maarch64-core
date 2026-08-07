use crate::{cpu::CpuContext, memory::MemoryManager, loader::TargetOs, Result};

pub mod linux;
pub mod darwin;

pub use linux::translate_open_flags;

pub struct SyscallDispatcher;

impl SyscallDispatcher {
    pub fn handle_syscall(ctx: &mut CpuContext, mem: &mut MemoryManager) -> Result<i64> {
        Self::handle_syscall_for_os(TargetOs::Linux, ctx, mem)
    }

    pub fn handle_syscall_for_os(target_os: TargetOs, ctx: &mut CpuContext, mem: &mut MemoryManager) -> Result<i64> {
        match target_os {
            TargetOs::Linux | TargetOs::Android => linux::LinuxSyscall::handle(ctx, mem),
            TargetOs::Darwin => {
                let nr = ctx.get_x(16); // macOS Darwin ARM64 syscall number is in X16
                darwin::DarwinSyscall::handle(nr, ctx, mem)
            }
        }
    }
}
