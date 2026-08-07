use crate::{cpu::CpuContext, memory::MemoryManager, Error, Result};
use bad64::{decode, Op, Reg, Operand, Imm};
use cranelift_codegen::ir::{types, Value, AbiParam, MemFlags, InstBuilder};
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
    ctx: CodeGenContext,
    module: JITModule,
    cache: HashMap<u64, CompiledBlock>,
    pub hits: u64,
    pub misses: u64,
}

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

fn is_zero_reg(reg: Reg) -> bool {
    matches!(reg, Reg::XZR | Reg::WZR)
}

fn is_w_reg(reg: Reg) -> bool {
    matches!(
        reg,
        Reg::W0 | Reg::W1 | Reg::W2 | Reg::W3 | Reg::W4 | Reg::W5 | Reg::W6 | Reg::W7 |
        Reg::W8 | Reg::W9 | Reg::W10 | Reg::W11 | Reg::W12 | Reg::W13 | Reg::W14 | Reg::W15 |
        Reg::W16 | Reg::W17 | Reg::W18 | Reg::W19 | Reg::W20 | Reg::W21 | Reg::W22 | Reg::W23 |
        Reg::W24 | Reg::W25 | Reg::W26 | Reg::W27 | Reg::W28 | Reg::W29 | Reg::W30 | Reg::WZR
    )
}

fn reg_idx(reg: Reg) -> Option<usize> {
    match reg {
        Reg::X0 | Reg::W0 => Some(0),
        Reg::X1 | Reg::W1 => Some(1),
        Reg::X2 | Reg::W2 => Some(2),
        Reg::X3 | Reg::W3 => Some(3),
        Reg::X4 | Reg::W4 => Some(4),
        Reg::X5 | Reg::W5 => Some(5),
        Reg::X6 | Reg::W6 => Some(6),
        Reg::X7 | Reg::W7 => Some(7),
        Reg::X8 | Reg::W8 => Some(8),
        Reg::X9 | Reg::W9 => Some(9),
        Reg::X10 | Reg::W10 => Some(10),
        Reg::X11 | Reg::W11 => Some(11),
        Reg::X12 | Reg::W12 => Some(12),
        Reg::X13 | Reg::W13 => Some(13),
        Reg::X14 | Reg::W14 => Some(14),
        Reg::X15 | Reg::W15 => Some(15),
        Reg::X16 | Reg::W16 => Some(16),
        Reg::X17 | Reg::W17 => Some(17),
        Reg::X18 | Reg::W18 => Some(18),
        Reg::X19 | Reg::W19 => Some(19),
        Reg::X20 | Reg::W20 => Some(20),
        Reg::X21 | Reg::W21 => Some(21),
        Reg::X22 | Reg::W22 => Some(22),
        Reg::X23 | Reg::W23 => Some(23),
        Reg::X24 | Reg::W24 => Some(24),
        Reg::X25 | Reg::W25 => Some(25),
        Reg::X26 | Reg::W26 => Some(26),
        Reg::X27 | Reg::W27 => Some(27),
        Reg::X28 | Reg::W28 => Some(28),
        Reg::X29 | Reg::W29 => Some(29),
        Reg::X30 | Reg::W30 => Some(30),
        _ => None,
    }
}

fn get_reg_offset(reg: Reg) -> Option<i32> {
    match reg {
        Reg::SP | Reg::WSP => Some(248),
        _ => {
            if let Some(idx) = reg_idx(reg) {
                Some((idx * 8) as i32)
            } else {
                None
            }
        }
    }
}

fn load_reg(builder: &mut FunctionBuilder, ctx_ptr: Value, reg: Reg) -> Value {
    if is_zero_reg(reg) {
        builder.ins().iconst(types::I64, 0)
    } else if let Some(off) = get_reg_offset(reg) {
        let val = builder.ins().load(types::I64, MemFlags::trusted(), ctx_ptr, off);
        if is_w_reg(reg) {
            let mask = builder.ins().iconst(types::I64, 0xffff_ffff);
            builder.ins().band(val, mask)
        } else {
            val
        }
    } else {
        builder.ins().iconst(types::I64, 0)
    }
}

fn store_reg(builder: &mut FunctionBuilder, ctx_ptr: Value, reg: Reg, val: Value) {
    if !is_zero_reg(reg) {
        if let Some(off) = get_reg_offset(reg) {
            let final_val = if is_w_reg(reg) {
                let mask = builder.ins().iconst(types::I64, 0xffff_ffff);
                builder.ins().band(val, mask)
            } else {
                val
            };
            builder.ins().store(MemFlags::trusted(), final_val, ctx_ptr, off);
        }
    }
}

impl JitEngine {
    pub fn new() -> Self {
        let builder = JITBuilder::new(cranelift_module::default_libcall_names()).unwrap();
        let module = JITModule::new(builder);
        let ctx = module.make_context();

        Self {
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

        self.ctx.func.signature.params.push(AbiParam::new(pointer_type)); // ctx
        self.ctx.func.signature.params.push(AbiParam::new(pointer_type)); // mem
        self.ctx.func.signature.returns.push(AbiParam::new(types::I64)); // next_pc

        let mut builder_ctx = FunctionBuilderContext::new();
        let mut builder = FunctionBuilder::new(&mut self.ctx.func, &mut builder_ctx);
        let entry_block = builder.create_block();
        builder.append_block_params_for_function_params(entry_block);
        builder.switch_to_block(entry_block);
        builder.seal_block(entry_block);

        let ctx_ptr = builder.block_params(entry_block)[0];

        let mut cur_pc = start_pc;
        let max_insts = 100;
        let mut inst_count = 0;
        let mut ended_block = false;
        let mut compiled_any = false;

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
                Op::NOP => {
                    compiled_any = true;
                }
                Op::MOV | Op::ORR => {
                    if operands.len() >= 2 {
                        if let (Some(rd), Some(rn)) = (get_op_reg(&operands[0]), get_op_reg(&operands[1])) {
                            let val_n = load_reg(&mut builder, ctx_ptr, rn);
                            store_reg(&mut builder, ctx_ptr, rd, val_n);
                            compiled_any = true;
                        } else if let Some(rd) = get_op_reg(&operands[0]) {
                            let imm_val = match &operands[1] {
                                Operand::Imm64 { imm, .. } | Operand::Imm32 { imm, .. } => imm_to_u64(imm),
                                Operand::Label(imm) => imm_to_u64(imm),
                                _ => 0,
                            };
                            let val_imm = builder.ins().iconst(types::I64, imm_val as i64);
                            store_reg(&mut builder, ctx_ptr, rd, val_imm);
                            compiled_any = true;
                        }
                    }
                }
                Op::ADD => {
                    if operands.len() >= 3 {
                        if let (Some(rd), Some(rn), Some(rm)) = (get_op_reg(&operands[0]), get_op_reg(&operands[1]), get_op_reg(&operands[2])) {
                            let val_n = load_reg(&mut builder, ctx_ptr, rn);
                            let val_m = load_reg(&mut builder, ctx_ptr, rm);
                            let res = builder.ins().iadd(val_n, val_m);
                            store_reg(&mut builder, ctx_ptr, rd, res);
                            compiled_any = true;
                        } else if let (Some(rd), Some(rn)) = (get_op_reg(&operands[0]), get_op_reg(&operands[1])) {
                            let imm_val = match &operands[2] {
                                Operand::Imm64 { imm, .. } | Operand::Imm32 { imm, .. } => imm_to_u64(imm),
                                Operand::Label(imm) => imm_to_u64(imm),
                                _ => 0,
                            };
                            let val_n = load_reg(&mut builder, ctx_ptr, rn);
                            let val_imm = builder.ins().iconst(types::I64, imm_val as i64);
                            let res = builder.ins().iadd(val_n, val_imm);
                            store_reg(&mut builder, ctx_ptr, rd, res);
                            compiled_any = true;
                        }
                    }
                }
                Op::SUB => {
                    if operands.len() >= 3 {
                        if let (Some(rd), Some(rn), Some(rm)) = (get_op_reg(&operands[0]), get_op_reg(&operands[1]), get_op_reg(&operands[2])) {
                            let val_n = load_reg(&mut builder, ctx_ptr, rn);
                            let val_m = load_reg(&mut builder, ctx_ptr, rm);
                            let res = builder.ins().isub(val_n, val_m);
                            store_reg(&mut builder, ctx_ptr, rd, res);
                            compiled_any = true;
                        } else if let (Some(rd), Some(rn)) = (get_op_reg(&operands[0]), get_op_reg(&operands[1])) {
                            let imm_val = match &operands[2] {
                                Operand::Imm64 { imm, .. } | Operand::Imm32 { imm, .. } => imm_to_u64(imm),
                                Operand::Label(imm) => imm_to_u64(imm),
                                _ => 0,
                            };
                            let val_n = load_reg(&mut builder, ctx_ptr, rn);
                            let val_imm = builder.ins().iconst(types::I64, imm_val as i64);
                            let res = builder.ins().isub(val_n, val_imm);
                            store_reg(&mut builder, ctx_ptr, rd, res);
                            compiled_any = true;
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
                    compiled_any = true;
                }
                Op::RET => {
                    let lr_val = load_reg(&mut builder, ctx_ptr, Reg::X30);
                    builder.ins().return_(&[lr_val]);
                    ended_block = true;
                    compiled_any = true;
                }
                Op::BL => {
                    let lr_val = builder.ins().iconst(types::I64, next_pc as i64);
                    store_reg(&mut builder, ctx_ptr, Reg::X30, lr_val);

                    let target_pc = match operands.first() {
                        Some(Operand::Label(imm)) => imm_to_u64(imm),
                        _ => next_pc,
                    };
                    let ret_val = builder.ins().iconst(types::I64, target_pc as i64);
                    builder.ins().return_(&[ret_val]);
                    ended_block = true;
                    compiled_any = true;
                }
                _ => {
                    if !compiled_any {
                        let ret_val = builder.ins().iconst(types::I64, cur_pc as i64);
                        builder.ins().return_(&[ret_val]);
                        builder.finalize();
                        return Err(Error::InterpreterError { pc: cur_pc, reason: "Unhandled JIT instruction".into() });
                    }
                    let ret_val = builder.ins().iconst(types::I64, cur_pc as i64);
                    builder.ins().return_(&[ret_val]);
                    ended_block = true;
                }
            }

            cur_pc += 4;
            inst_count += 1;
        }

        if !compiled_any {
            let ret_val = builder.ins().iconst(types::I64, start_pc as i64);
            builder.ins().return_(&[ret_val]);
            builder.finalize();
            return Err(Error::InterpreterError { pc: start_pc, reason: "No JIT instructions compiled".into() });
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
        match self.compile_and_get(pc, mem) {
            Ok(block) => {
                let next_pc = unsafe { (block.func_ptr)(ctx, mem) };
                if next_pc != pc {
                    ctx.pc = next_pc;
                    Ok(!ctx.exited)
                } else {
                    crate::interp::Interpreter::step(ctx, mem)
                }
            }
            Err(_) => {
                crate::interp::Interpreter::step(ctx, mem)
            }
        }
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
