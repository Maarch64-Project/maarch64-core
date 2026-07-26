use crate::{cpu::CpuContext, memory::MemoryManager, Result};
use bad64::{decode, Instruction, Op};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub start_pc: u64,
    pub end_pc: u64,
    pub instructions: Vec<Instruction>,
    pub successor_pcs: Vec<u64>,
}

#[derive(Debug)]
pub struct JitCache {
    blocks: HashMap<u64, BasicBlock>,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub chained_jumps: u64,
}

impl JitCache {
    pub fn new() -> Self {
        Self {
            blocks: HashMap::new(),
            cache_hits: 0,
            cache_misses: 0,
            chained_jumps: 0,
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
        let mut successor_pcs = Vec::new();

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
                // Record fall-through and target successors if statically computable
                successor_pcs.push(cur_pc);
                break;
            }
        }

        let block = BasicBlock {
            start_pc,
            end_pc: cur_pc,
            instructions,
            successor_pcs,
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

    /// Execute basic blocks with direct chaining (block-to-block jumps without returning to top-level dispatcher).
    pub fn execute_block_chain(
        &mut self,
        ctx: &mut CpuContext,
        mem: &mut MemoryManager,
        max_chain: usize,
    ) -> Result<bool> {
        let mut chain_count = 0;

        while chain_count < max_chain {
            if ctx.exited {
                return Ok(false);
            }

            let pc = ctx.pc;
            if !self.blocks.contains_key(&pc) {
                if self.compile_block(pc, mem).is_err() {
                    break;
                }
                self.cache_misses += 1;
            } else {
                self.cache_hits += 1;
            }

            let block = match self.blocks.get(&pc) {
                Some(b) => b.clone(),
                None => break,
            };

            Self::execute_block(&block, ctx, mem)?;

            chain_count += 1;
            if chain_count > 1 {
                self.chained_jumps += 1;
            }

            if ctx.exited || ctx.pc == pc {
                break;
            }
        }

        Ok(!ctx.exited)
    }
}
