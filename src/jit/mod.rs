use crate::{cpu::CpuContext, memory::MemoryManager, Result};
use bad64::{decode, Instruction, Op};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub start_pc: u64,
    pub end_pc: u64,
    pub instructions: Vec<Instruction>,
}

#[derive(Debug)]
pub struct JitCache {
    blocks: HashMap<u64, BasicBlock>,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

impl JitCache {
    pub fn new() -> Self {
        Self {
            blocks: HashMap::new(),
            cache_hits: 0,
            cache_misses: 0,
        }
    }

    pub fn contains(&self, pc: u64) -> bool {
        self.blocks.contains_key(&pc)
    }

    pub fn get_block(&mut self, pc: u64) -> Option<&BasicBlock> {
        if self.blocks.contains_key(&pc) {
            self.cache_hits += 1;
            self.blocks.get(&pc)
        } else {
            self.cache_misses += 1;
            None
        }
    }

    pub fn compile_block(&mut self, start_pc: u64, mem: &MemoryManager) -> Result<&BasicBlock> {
        let mut cur_pc = start_pc;
        let mut instructions = Vec::new();
        let max_block_instructions = 500;

        while instructions.len() < max_block_instructions {
            let ins_bytes = match mem.read(cur_pc, 4) {
                Ok(b) => b,
                Err(_) => break,
            };
            let ins_u32 = u32::from_le_bytes(ins_bytes.try_into().unwrap());
            let inst = match decode(ins_u32, cur_pc) {
                Ok(i) => i,
                Err(_) => break,
            };

            let op = inst.op();
            instructions.push(inst);
            cur_pc += 4;

            // Bounded basic block ends at branch, jump, or system call
            if matches!(
                op,
                Op::B
                    | Op::BL
                    | Op::RET
                    | Op::CBZ
                    | Op::CBNZ
                    | Op::BR
                    | Op::BLR
                    | Op::SVC
            ) {
                break;
            }
        }

        let block = BasicBlock {
            start_pc,
            end_pc: cur_pc,
            instructions,
        };

        self.blocks.insert(start_pc, block);
        Ok(self.blocks.get(&start_pc).unwrap())
    }

    pub fn execute_block(
        block: &BasicBlock,
        ctx: &mut CpuContext,
        mem: &mut MemoryManager,
    ) -> Result<()> {
        for _inst in &block.instructions {
            if ctx.exited {
                break;
            }
            crate::interp::Interpreter::step(ctx, mem)?;
        }
        Ok(())
    }
}
