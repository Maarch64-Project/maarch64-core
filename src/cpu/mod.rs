/// ARM64 (AArch64) CPU Register State & Execution Context
#[derive(Debug, Clone, Default)]
pub struct CpuContext {
    /// General-purpose registers X0..X30 (X30 is LR)
    pub x: [u64; 31],
    /// Stack Pointer (SP)
    pub sp: u64,
    /// Program Counter (PC)
    pub pc: u64,
    /// Process State (NZCV flags)
    pub pstate: u32,
    /// Floating point / SIMD registers V0..V31 (128-bit each)
    pub v: [[u8; 16]; 32],
}

impl CpuContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_x(&mut self, reg: usize, val: u64) {
        if reg < 31 {
            self.x[reg] = val;
        }
    }

    pub fn get_x(&self, reg: usize) -> u64 {
        if reg < 31 {
            self.x[reg]
        } else {
            0
        }
    }
}
