/// ARM64 (AArch64) CPU Register State & Execution Context
#[derive(Debug, Clone, Default)]
pub struct CpuContext {
    /// General-purpose registers X0..X30 (X30 is LR)
    pub x: [u64; 31],
    /// Stack Pointer (SP)
    pub sp: u64,
    /// Program Counter (PC)
    pub pc: u64,
    /// Process State (NZCV flags: N=bit31, Z=bit30, C=bit29, V=bit28)
    pub pstate: u32,
    /// Floating point / SIMD registers V0..V31 (128-bit each)
    pub v: [[u8; 16]; 32],
    /// Thread ID / Thread Local Storage register (TPIDR_EL0)
    pub tpidr_el0: u64,
    /// Process exit flag
    pub exited: bool,
    /// Process exit status code
    pub exit_code: i32,
}

pub const FLAG_N: u32 = 1 << 31;
pub const FLAG_Z: u32 = 1 << 30;
pub const FLAG_C: u32 = 1 << 29;
pub const FLAG_V: u32 = 1 << 28;

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

    pub fn get_n(&self) -> bool {
        (self.pstate & FLAG_N) != 0
    }

    pub fn get_z(&self) -> bool {
        (self.pstate & FLAG_Z) != 0
    }

    pub fn get_c(&self) -> bool {
        (self.pstate & FLAG_C) != 0
    }

    pub fn get_v(&self) -> bool {
        (self.pstate & FLAG_V) != 0
    }

    pub fn set_nzcv(&mut self, n: bool, z: bool, c: bool, v: bool) {
        let mut flags = 0u32;
        if n { flags |= FLAG_N; }
        if z { flags |= FLAG_Z; }
        if c { flags |= FLAG_C; }
        if v { flags |= FLAG_V; }
        self.pstate = (self.pstate & 0x0fffffff) | flags;
    }
    pub fn get_v_u64(&self, reg: usize) -> u64 {
        if reg < 32 {
            u64::from_le_bytes(self.v[reg][0..8].try_into().unwrap())
        } else {
            0
        }
    }

    pub fn set_v_u64(&mut self, reg: usize, val: u64) {
        if reg < 32 {
            self.v[reg][0..8].copy_from_slice(&val.to_le_bytes());
            self.v[reg][8..16].fill(0);
        }
    }

    pub fn get_v_u128(&self, reg: usize) -> u128 {
        if reg < 32 {
            u128::from_le_bytes(self.v[reg])
        } else {
            0
        }
    }

    pub fn set_v_u128(&mut self, reg: usize, val: u128) {
        if reg < 32 {
            self.v[reg].copy_from_slice(&val.to_le_bytes());
        }
    }
}
