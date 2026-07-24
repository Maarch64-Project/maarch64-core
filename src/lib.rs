pub mod cpu;
pub mod decoder;
pub mod interp;
pub mod jit;
pub mod loader;
pub mod memory;
pub mod syscall;

pub use cpu::CpuContext;
pub use loader::ElfLoader;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to load binary: {0}")]
    LoadError(String),
    #[error("Memory error: {0}")]
    MemoryError(String),
    #[error("Instruction decode error at PC {pc:#x}: {reason}")]
    DecodeError { pc: u64, reason: String },
    #[error("Unhandled syscall number: {0}")]
    UnhandledSyscall(u64),
}

pub type Result<T> = std::result::Result<T, Error>;
