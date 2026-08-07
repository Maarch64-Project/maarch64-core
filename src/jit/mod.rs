use crate::{cpu::CpuContext, memory::MemoryManager, Error, Result};
use bad64::{decode, Op, Reg, Operand, Imm};
use cranelift_codegen::ir::{types, AbiParam, MemFlags, InstBuilder};
use cranelift_codegen::Context as CodeGenContext;
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{Linkage, Module};
use std::collections::HashMap;

pub type JitBlockFn = unsafe extern "C" fn(*mut CpuContext, *mut MemoryManager) -> u64;

#[derive(Clone)]
pub struct CompiledBlock {
    pub start_pc: u64,
    pub end_pc: u64,
    pub func_ptr: JitBlockFn,
}

pub struct JitEngine {
    builder_ctx: FunctionBuilderContext,
    ctx: CodeGenContext,
    module: JITModule,
    cache: HashMap<u64, CompiledBlock>,
    pub hits: u64,
    pub misses: u64,
}

// Retain JitCache alias for backwards compatibility
pub type JitCache = JitEngine;

fn imm_to_u64(imm: &Imm) -> u64 {
    match imm {
        Imm::Signed(i) => *i as u64,
        Imm::Unsigned(u) => *u,
    }
}

fn get_op_reg(op: &Operand) -> Option<Reg> {
    match op {
        Operand::Reg { reg, .. } => Some(*reg),
        Operand::QualReg { reg, .. } => Some(*reg),
        Operand::ShiftReg { reg, .. } => Some(*reg),
        _ => None,
    }
}

fn get_reg_offset(reg: Reg) -> i32 {
    match reg {
        Reg::SP | Reg::WSP => 248,
        _ => {
            let idx = reg as usize;
            if idx <= 30 { (idx * 8) as i32 } else { 248 }
        }
    }
}

impl JitEngine {
    pub fn new() -> Self {
        let builder = JITBuilder::new(cranelift_module::default_libcall_names()).unwrap();
        let module = JITModule::new(builder);
        let ctx = module.make_context();
        let builder_ctx = FunctionBuilderContext::new();

        Self {
            builder_ctx,
            ctx,
            module,
            cache: HashMap::new(),
            hits: 0,
            misses: 0,
        }
    }

    pub fn is_cached(&self, pc: u64) -> bool {
        self.cache.contains_key(&pc)
    }

    pub fn get_block(&mut self, pc: u64) -> Option<&CompiledBlock> {
        if self.cache.contains_key(&pc) {
            self.hits += 1;
            self.cache.get(&pc)
        } else {
            self.misses += 1;
            None
        }
    }

    pub fn compile_and_get(&mut self, start_pc: u64, mem: &MemoryManager) -> Result<CompiledBlock> {
        if let Some(block) = self.cache.get(&start_pc) {
            return Ok(block.clone());
        }

        self.ctx.clear();
        let pointer_type = self.module.target_config().pointer_type();

        // Signature: fn(ctx: *mut CpuContext, mem: *mut MemoryManager) -> u64 (next_pc)
        self.ctx.func.signature.params.push(AbiParam::new(pointer_type)); // ctx
        self.ctx.func.signature.params.push(AbiParam::new(pointer_type)); // mem
        self.ctx.func.signature.returns.push(AbiParam::new(types::I64)); // next_pc

        let mut builder = FunctionBuilder::new(&mut self.ctx.func, &mut self.builder_ctx);
        let entry_block = builder.create_block();
        builder.append_block_params_for_function_params(entry_block);
        builder.switch_to_block(entry_block);
        builder.seal_block(entry_block);

        let ctx_ptr = builder.block_params(entry_block)[0];

        let mut cur_pc = start_pc;
        let max_insts = 100;
        let mut inst_count = 0;
        let mut ended_block = false;

        while inst_count < max_insts && !ended_block {
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
            let next_pc = cur_pc + 4;
            let operands = inst.operands();

            match op {
                Op::NOP => {}
                Op::MOV | Op::ORR => {
                    if operands.len() >= 2 {
                        if let (Some(rd), Some(rn)) = (get_op_reg(&operands[0]), get_op_reg(&operands[1])) {
                            let off_n = get_reg_offset(rn);
                            let val_n = builder.ins().load(types::I64, MemFlags::trusted(), ctx_ptr, off_n);
                            let off_d = get_reg_offset(rd);
                            builder.ins().store(MemFlags::trusted(), val_n, ctx_ptr, off_d);
                        } else if let Some(rd) = get_op_reg(&operands[0]) {
                            let imm_val = match &operands[1] {
                                Operand::Imm64 { imm, .. } | Operand::Imm32 { imm, .. } => imm_to_u64(imm),
                                Operand::Label(imm) => imm_to_u64(imm),
                                _ => 0,
                            };
                            let val_imm = builder.ins().iconst(types::I64, imm_val as i64);
                            let off_d = get_reg_offset(rd);
                            builder.ins().store(MemFlags::trusted(), val_imm, ctx_ptr, off_d);
                        }
                    }
                }
                Op::ADD => {
                    if operands.len() >= 3 {
                        if let (Some(rd), Some(rn), Some(rm)) = (get_op_reg(&operands[0]), get_op_reg(&operands[1]), get_op_reg(&operands[2])) {
                            let val_n = builder.ins().load(types::I64, MemFlags::trusted(), ctx_ptr, get_reg_offset(rn));
                            let val_m = builder.ins().load(types::I64, MemFlags::trusted(), ctx_ptr, get_reg_offset(rm));
                            let res = builder.ins().iadd(val_n, val_m);
                            builder.ins().store(MemFlags::trusted(), res, ctx_ptr, get_reg_offset(rd));
                        } else if let (Some(rd), Some(rn)) = (get_op_reg(&operands[0]), get_op_reg(&operands[1])) {
                            let imm_val = match &operands[2] {
                                Operand::Imm64 { imm, .. } | Operand::Imm32 { imm, .. } => imm_to_u64(imm),
                                Operand::Label(imm) => imm_to_u64(imm),
                                _ => 0,
                            };
                            let val_n = builder.ins().load(types::I64, MemFlags::trusted(), ctx_ptr, get_reg_offset(rn));
                            let val_imm = builder.ins().iconst(types::I64, imm_val as i64);
                            let res = builder.ins().iadd(val_n, val_imm);
                            builder.ins().store(MemFlags::trusted(), res, ctx_ptr, get_reg_offset(rd));
                        }
                    }
                }
                Op::SUB => {
                    if operands.len() >= 3 {
                        if let (Some(rd), Some(rn), Some(rm)) = (get_op_reg(&operands[0]), get_op_reg(&operands[1]), get_op_reg(&operands[2])) {
                            let val_n = builder.ins().load(types::I64, MemFlags::trusted(), ctx_ptr, get_reg_offset(rn));
                            let val_m = builder.ins().load(types::I64, MemFlags::trusted(), ctx_ptr, get_reg_offset(rm));
                            let res = builder.ins().isub(val_n, val_m);
                            builder.ins().store(MemFlags::trusted(), res, ctx_ptr, get_reg_offset(rd));
                        } else if let (Some(rd), Some(rn)) = (get_op_reg(&operands[0]), get_op_reg(&operands[1])) {
                            let imm_val = match &operands[2] {
                                Operand::Imm64 { imm, .. } | Operand::Imm32 { imm, .. } => imm_to_u64(imm),
                                Operand::Label(imm) => imm_to_u64(imm),
                                _ => 0,
                            };
                            let val_n = builder.ins().load(types::I64, MemFlags::trusted(), ctx_ptr, get_reg_offset(rn));
                            let val_imm = builder.ins().iconst(types::I64, imm_val as i64);
                            let res = builder.ins().isub(val_n, val_imm);
                            builder.ins().store(MemFlags::trusted(), res, ctx_ptr, get_reg_offset(rd));
                        }
                    }
                }
                Op::B => {
                    let target_pc = match operands.first() {
                        Some(Operand::Label(imm)) => imm_to_u64(imm),
                        _ => next_pc,
                    };
                    let ret_val = builder.ins().iconst(types::I64, target_pc as i64);
                    builder.ins().return_(&[ret_val]);
                    ended_block = true;
                }
                Op::RET => {
                    let lr_val = builder.ins().load(types::I64, MemFlags::trusted(), ctx_ptr, 30 * 8);
                    builder.ins().return_(&[lr_val]);
                    ended_block = true;
                }
                Op::BL => {
                    let lr_val = builder.ins().iconst(types::I64, next_pc as i64);
                    builder.ins().store(MemFlags::trusted(), lr_val, ctx_ptr, 30 * 8);

                    let target_pc = match operands.first() {
                        Some(Operand::Label(imm)) => imm_to_u64(imm),
                        _ => next_pc,
                    };
                    let ret_val = builder.ins().iconst(types::I64, target_pc as i64);
                    builder.ins().return_(&[ret_val]);
                    ended_block = true;
                }
                _ => {
                    // Fallback to interpreter for unhandled instructions
                    let ret_val = builder.ins().iconst(types::I64, cur_pc as i64);
                    builder.ins().return_(&[ret_val]);
                    ended_block = true;
                }
            }

            cur_pc += 4;
            inst_count += 1;
        }

        if !ended_block {
            let ret_val = builder.ins().iconst(types::I64, cur_pc as i64);
            builder.ins().return_(&[ret_val]);
        }

        builder.finalize();

        let func_id = self.module
            .declare_function(&format!("jit_block_{:x}", start_pc), Linkage::Local, &self.ctx.func.signature)
            .map_err(|e| Error::InterpreterError { pc: start_pc, reason: format!("JIT declare error: {}", e) })?;

        self.module
            .define_function(func_id, &mut self.ctx)
            .map_err(|e| Error::InterpreterError { pc: start_pc, reason: format!("JIT define error: {}", e) })?;

        self.module.clear_context(&mut self.ctx);
        self.module.finalize_definitions()
            .map_err(|e| Error::InterpreterError { pc: start_pc, reason: format!("JIT finalize error: {}", e) })?;

        let raw_ptr = self.module.get_finalized_function(func_id);
        let func_ptr: JitBlockFn = unsafe { std::mem::transmute(raw_ptr) };

        let block = CompiledBlock {
            start_pc,
            end_pc: cur_pc,
            func_ptr,
        };

        self.cache.insert(start_pc, block.clone());
        Ok(block)
    }

    pub fn execute(&mut self, ctx: &mut CpuContext, mem: &mut MemoryManager) -> Result<bool> {
        let pc = ctx.pc;
        let block = self.compile_and_get(pc, mem)?;
        let next_pc = unsafe { (block.func_ptr)(ctx, mem) };
        ctx.pc = next_pc;
        Ok(!ctx.exited)
    }

    pub fn execute_block_chain(
        &mut self,
        ctx: &mut CpuContext,
        mem: &mut MemoryManager,
        max_chain: usize,
    ) -> Result<bool> {
        let mut count = 0;
        while count < max_chain && !ctx.exited {
            let res = self.execute(ctx, mem)?;
            if !res {
                break;
            }
            count += 1;
        }
        Ok(!ctx.exited)
    }
}
