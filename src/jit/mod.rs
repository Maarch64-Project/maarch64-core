use crate::Result;

pub trait JitEngine {
    fn compile_block(&mut self, address: u64, code: &[u8]) -> Result<*const u8>;
    fn invalidate(&mut self, address: u64);
}

pub struct DirectJitEngine;

impl DirectJitEngine {
    pub fn new() -> Self {
        Self
    }
}

impl JitEngine for DirectJitEngine {
    fn compile_block(&mut self, _address: u64, _code: &[u8]) -> Result<*const u8> {
        // Fast direct code generation stub
        Ok(std::ptr::null())
    }

    fn invalidate(&mut self, _address: u64) {}
}
