use crate::{cpu::CpuContext, memory::MemoryManager, Error, Result};
use bad64::{decode, Op, Reg, Operand, Imm};
use cranelift_codegen::ir::{types, Value, AbiParam, MemFlags, InstBuilder};
use cranelift_codegen::ir::condcodes::IntCC;
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
        Reg::W24 | Reg::W25 | Reg::W26 | Reg::W27 | Reg::W28 | Reg::W29 | Reg::W30 | Reg::WZR | Reg::WSP
    )
}

fn v_reg_idx(reg: Reg) -> Option<usize> {
    match reg {
        Reg::V0 | Reg::D0 | Reg::S0 | Reg::H0 | Reg::B0 | Reg::Q0 => Some(0),
        Reg::V1 | Reg::D1 | Reg::S1 | Reg::H1 | Reg::B1 | Reg::Q1 => Some(1),
        Reg::V2 | Reg::D2 | Reg::S2 | Reg::H2 | Reg::B2 | Reg::Q2 => Some(2),
        Reg::V3 | Reg::D3 | Reg::S3 | Reg::H3 | Reg::B3 | Reg::Q3 => Some(3),
        Reg::V4 | Reg::D4 | Reg::S4 | Reg::H4 | Reg::B4 | Reg::Q4 => Some(4),
        Reg::V5 | Reg::D5 | Reg::S5 | Reg::H5 | Reg::B5 | Reg::Q5 => Some(5),
        Reg::V6 | Reg::D6 | Reg::S6 | Reg::H6 | Reg::B6 | Reg::Q6 => Some(6),
        Reg::V7 | Reg::D7 | Reg::S7 | Reg::H7 | Reg::B7 | Reg::Q7 => Some(7),
        Reg::V8 | Reg::D8 | Reg::S8 | Reg::H8 | Reg::B8 | Reg::Q8 => Some(8),
        Reg::V9 | Reg::D9 | Reg::S9 | Reg::H9 | Reg::B9 | Reg::Q9 => Some(9),
        Reg::V10 | Reg::D10 | Reg::S10 | Reg::H10 | Reg::B10 | Reg::Q10 => Some(10),
        Reg::V11 | Reg::D11 | Reg::S11 | Reg::H11 | Reg::B11 | Reg::Q11 => Some(11),
        Reg::V12 | Reg::D12 | Reg::S12 | Reg::H12 | Reg::B12 | Reg::Q12 => Some(12),
        Reg::V13 | Reg::D13 | Reg::S13 | Reg::H13 | Reg::B13 | Reg::Q13 => Some(13),
        Reg::V14 | Reg::D14 | Reg::S14 | Reg::H14 | Reg::B14 | Reg::Q14 => Some(14),
        Reg::V15 | Reg::D15 | Reg::S15 | Reg::H15 | Reg::B15 | Reg::Q15 => Some(15),
        Reg::V16 | Reg::D16 | Reg::S16 | Reg::H16 | Reg::B16 | Reg::Q16 => Some(16),
        Reg::V17 | Reg::D17 | Reg::S17 | Reg::H17 | Reg::B17 | Reg::Q17 => Some(17),
        Reg::V18 | Reg::D18 | Reg::S18 | Reg::H18 | Reg::B18 | Reg::Q18 => Some(18),
        Reg::V19 | Reg::D19 | Reg::S19 | Reg::H19 | Reg::B19 | Reg::Q19 => Some(19),
        Reg::V20 | Reg::D20 | Reg::S20 | Reg::H20 | Reg::B20 | Reg::Q20 => Some(20),
        Reg::V21 | Reg::D21 | Reg::S21 | Reg::H21 | Reg::B21 | Reg::Q21 => Some(21),
        Reg::V22 | Reg::D22 | Reg::S22 | Reg::H22 | Reg::B22 | Reg::Q22 => Some(22),
        Reg::V23 | Reg::D23 | Reg::S23 | Reg::H23 | Reg::B23 | Reg::Q23 => Some(23),
        Reg::V24 | Reg::D24 | Reg::S24 | Reg::H24 | Reg::B24 | Reg::Q24 => Some(24),
        Reg::V25 | Reg::D25 | Reg::S25 | Reg::H25 | Reg::B25 | Reg::Q25 => Some(25),
        Reg::V26 | Reg::D26 | Reg::S26 | Reg::H26 | Reg::B26 | Reg::Q26 => Some(26),
        Reg::V27 | Reg::D27 | Reg::S27 | Reg::H27 | Reg::B27 | Reg::Q27 => Some(27),
        Reg::V28 | Reg::D28 | Reg::S28 | Reg::H28 | Reg::B28 | Reg::Q28 => Some(28),
        Reg::V29 | Reg::D29 | Reg::S29 | Reg::H29 | Reg::B29 | Reg::Q29 => Some(29),
        Reg::V30 | Reg::D30 | Reg::S30 | Reg::H30 | Reg::B30 | Reg::Q30 => Some(30),
        Reg::V31 | Reg::D31 | Reg::S31 | Reg::H31 | Reg::B31 | Reg::Q31 => Some(31),
        _ => None,
    }
}

fn get_v_reg_offset(reg: Reg) -> Option<i32> {
    v_reg_idx(reg).map(|idx| (272 + idx * 16) as i32)
}

fn load_v_f64(builder: &mut FunctionBuilder, ctx_ptr: Value, reg: Reg) -> Value {
    if let Some(off) = get_v_reg_offset(reg) {
        builder.ins().load(types::F64, MemFlags::trusted(), ctx_ptr, off)
    } else {
        builder.ins().f64const(0.0)
    }
}

fn store_v_f64(builder: &mut FunctionBuilder, ctx_ptr: Value, reg: Reg, val: Value) {
    if let Some(off) = get_v_reg_offset(reg) {
        builder.ins().store(MemFlags::trusted(), val, ctx_ptr, off);
        let zero64 = builder.ins().iconst(types::I64, 0);
        builder.ins().store(MemFlags::trusted(), zero64, ctx_ptr, off + 8);
    }
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
        Reg::SP | Reg::WSP => Some(31),
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
                Op::ADRP => {
                    if let (Some(rd), Some(target_op)) = (operands.first().and_then(get_op_reg), operands.get(1)) {
                        let page_base = match target_op {
                            Operand::Label(imm) => imm_to_u64(imm),
                            _ => cur_pc & !0xFFF,
                        };
                        let val_page = builder.ins().iconst(types::I64, page_base as i64);
                        store_reg(&mut builder, ctx_ptr, rd, val_page);
                        compiled_any = true;
                    }
                }
                Op::AND => {
                    if let (Some(rd), Some(rn)) = (operands.get(0).and_then(get_op_reg), operands.get(1).and_then(get_op_reg)) {
                        let val_n = load_reg(&mut builder, ctx_ptr, rn);
                        let val_m = if let Some(rm) = operands.get(2).and_then(get_op_reg) {
                            load_reg(&mut builder, ctx_ptr, rm)
                        } else {
                            let imm_val = operands.get(2).map(|op| match op {
                                Operand::Imm64 { imm, .. } | Operand::Imm32 { imm, .. } => imm_to_u64(imm),
                                _ => 0,
                            }).unwrap_or(0);
                            builder.ins().iconst(types::I64, imm_val as i64)
                        };
                        let res = builder.ins().band(val_n, val_m);
                        store_reg(&mut builder, ctx_ptr, rd, res);
                        compiled_any = true;
                    }
                }
                Op::EOR => {
                    if let (Some(rd), Some(rn)) = (operands.get(0).and_then(get_op_reg), operands.get(1).and_then(get_op_reg)) {
                        let val_n = load_reg(&mut builder, ctx_ptr, rn);
                        let val_m = if let Some(rm) = operands.get(2).and_then(get_op_reg) {
                            load_reg(&mut builder, ctx_ptr, rm)
                        } else {
                            let imm_val = operands.get(2).map(|op| match op {
                                Operand::Imm64 { imm, .. } | Operand::Imm32 { imm, .. } => imm_to_u64(imm),
                                _ => 0,
                            }).unwrap_or(0);
                            builder.ins().iconst(types::I64, imm_val as i64)
                        };
                        let res = builder.ins().bxor(val_n, val_m);
                        store_reg(&mut builder, ctx_ptr, rd, res);
                        compiled_any = true;
                    }
                }
                Op::LSL => {
                    if let (Some(rd), Some(rn)) = (operands.get(0).and_then(get_op_reg), operands.get(1).and_then(get_op_reg)) {
                        let val_n = load_reg(&mut builder, ctx_ptr, rn);
                        let shift_val = if let Some(rm) = operands.get(2).and_then(get_op_reg) {
                            load_reg(&mut builder, ctx_ptr, rm)
                        } else {
                            let imm_val = operands.get(2).map(|op| match op {
                                Operand::Imm64 { imm, .. } | Operand::Imm32 { imm, .. } => imm_to_u64(imm),
                                _ => 0,
                            }).unwrap_or(0);
                            builder.ins().iconst(types::I64, imm_val as i64)
                        };
                        let res = builder.ins().ishl(val_n, shift_val);
                        store_reg(&mut builder, ctx_ptr, rd, res);
                        compiled_any = true;
                    }
                }
                Op::LSR => {
                    if let (Some(rd), Some(rn)) = (operands.get(0).and_then(get_op_reg), operands.get(1).and_then(get_op_reg)) {
                        let val_n = load_reg(&mut builder, ctx_ptr, rn);
                        let shift_val = if let Some(rm) = operands.get(2).and_then(get_op_reg) {
                            load_reg(&mut builder, ctx_ptr, rm)
                        } else {
                            let imm_val = operands.get(2).map(|op| match op {
                                Operand::Imm64 { imm, .. } | Operand::Imm32 { imm, .. } => imm_to_u64(imm),
                                _ => 0,
                            }).unwrap_or(0);
                            builder.ins().iconst(types::I64, imm_val as i64)
                        };
                        let res = builder.ins().ushr(val_n, shift_val);
                        store_reg(&mut builder, ctx_ptr, rd, res);
                        compiled_any = true;
                    }
                }
                Op::ASR => {
                    if let (Some(rd), Some(rn)) = (operands.get(0).and_then(get_op_reg), operands.get(1).and_then(get_op_reg)) {
                        let val_n = load_reg(&mut builder, ctx_ptr, rn);
                        let shift_val = if let Some(rm) = operands.get(2).and_then(get_op_reg) {
                            load_reg(&mut builder, ctx_ptr, rm)
                        } else {
                            let imm_val = operands.get(2).map(|op| match op {
                                Operand::Imm64 { imm, .. } | Operand::Imm32 { imm, .. } => imm_to_u64(imm),
                                _ => 0,
                            }).unwrap_or(0);
                            builder.ins().iconst(types::I64, imm_val as i64)
                        };
                        let res = builder.ins().sshr(val_n, shift_val);
                        store_reg(&mut builder, ctx_ptr, rd, res);
                        compiled_any = true;
                    }
                }
                Op::CBZ => {
                    if let (Some(rt), Some(target_op)) = (operands.first().and_then(get_op_reg), operands.get(1)) {
                        let target_pc = match target_op {
                            Operand::Label(imm) => imm_to_u64(imm),
                            _ => next_pc,
                        };
                        let val_t = load_reg(&mut builder, ctx_ptr, rt);
                        let zero = builder.ins().iconst(types::I64, 0);
                        let cond = builder.ins().icmp(IntCC::Equal, val_t, zero);
                        let ret_target = builder.ins().iconst(types::I64, target_pc as i64);
                        let ret_next = builder.ins().iconst(types::I64, next_pc as i64);
                        let res_pc = builder.ins().select(cond, ret_target, ret_next);
                        builder.ins().return_(&[res_pc]);
                        ended_block = true;
                        compiled_any = true;
                    }
                }
                Op::CBNZ => {
                    if let (Some(rt), Some(target_op)) = (operands.first().and_then(get_op_reg), operands.get(1)) {
                        let target_pc = match target_op {
                            Operand::Label(imm) => imm_to_u64(imm),
                            _ => next_pc,
                        };
                        let val_t = load_reg(&mut builder, ctx_ptr, rt);
                        let zero = builder.ins().iconst(types::I64, 0);
                        let cond = builder.ins().icmp(IntCC::NotEqual, val_t, zero);
                        let ret_target = builder.ins().iconst(types::I64, target_pc as i64);
                        let ret_next = builder.ins().iconst(types::I64, next_pc as i64);
                        let res_pc = builder.ins().select(cond, ret_target, ret_next);
                        builder.ins().return_(&[res_pc]);
                        ended_block = true;
                        compiled_any = true;
                    }
                }
                Op::FADD => {
                    if let (Some(vd), Some(vn), Some(vm)) = (operands.get(0).and_then(get_op_reg), operands.get(1).and_then(get_op_reg), operands.get(2).and_then(get_op_reg)) {
                        let val_n = load_v_f64(&mut builder, ctx_ptr, vn);
                        let val_m = load_v_f64(&mut builder, ctx_ptr, vm);
                        let res = builder.ins().fadd(val_n, val_m);
                        store_v_f64(&mut builder, ctx_ptr, vd, res);
                        compiled_any = true;
                    }
                }
                Op::FSUB => {
                    if let (Some(vd), Some(vn), Some(vm)) = (operands.get(0).and_then(get_op_reg), operands.get(1).and_then(get_op_reg), operands.get(2).and_then(get_op_reg)) {
                        let val_n = load_v_f64(&mut builder, ctx_ptr, vn);
                        let val_m = load_v_f64(&mut builder, ctx_ptr, vm);
                        let res = builder.ins().fsub(val_n, val_m);
                        store_v_f64(&mut builder, ctx_ptr, vd, res);
                        compiled_any = true;
                    }
                }
                Op::FMUL => {
                    if let (Some(vd), Some(vn), Some(vm)) = (operands.get(0).and_then(get_op_reg), operands.get(1).and_then(get_op_reg), operands.get(2).and_then(get_op_reg)) {
                        let val_n = load_v_f64(&mut builder, ctx_ptr, vn);
                        let val_m = load_v_f64(&mut builder, ctx_ptr, vm);
                        let res = builder.ins().fmul(val_n, val_m);
                        store_v_f64(&mut builder, ctx_ptr, vd, res);
                        compiled_any = true;
                    }
                }
                Op::FDIV => {
                    if let (Some(vd), Some(vn), Some(vm)) = (operands.get(0).and_then(get_op_reg), operands.get(1).and_then(get_op_reg), operands.get(2).and_then(get_op_reg)) {
                        let val_n = load_v_f64(&mut builder, ctx_ptr, vn);
                        let val_m = load_v_f64(&mut builder, ctx_ptr, vm);
                        let res = builder.ins().fdiv(val_n, val_m);
                        store_v_f64(&mut builder, ctx_ptr, vd, res);
                        compiled_any = true;
                    }
                }
                Op::FMOV => {
                    if let (Some(rd), Some(rn)) = (operands.get(0).and_then(get_op_reg), operands.get(1).and_then(get_op_reg)) {
                        if v_reg_idx(rd).is_some() && v_reg_idx(rn).is_some() {
                            let val_n = load_v_f64(&mut builder, ctx_ptr, rn);
                            store_v_f64(&mut builder, ctx_ptr, rd, val_n);
                            compiled_any = true;
                        } else if v_reg_idx(rd).is_some() {
                            let val_n = load_reg(&mut builder, ctx_ptr, rn);
                            let fval = builder.ins().bitcast(types::F64, MemFlags::trusted(), val_n);
                            store_v_f64(&mut builder, ctx_ptr, rd, fval);
                            compiled_any = true;
                        } else if v_reg_idx(rn).is_some() {
                            let val_n = load_v_f64(&mut builder, ctx_ptr, rn);
                            let ival = builder.ins().bitcast(types::I64, MemFlags::trusted(), val_n);
                            store_reg(&mut builder, ctx_ptr, rd, ival);
                            compiled_any = true;
                        }
                    }
                }
                Op::MRS => {
                    if let Some(rt) = operands.first().and_then(get_op_reg) {
                        let tpidr_off = 784i32;
                        let tpidr_val = builder.ins().load(types::I64, MemFlags::trusted(), ctx_ptr, tpidr_off);
                        store_reg(&mut builder, ctx_ptr, rt, tpidr_val);
                        compiled_any = true;
                    }
                }
                Op::MSR => {
                    if let Some(rt) = operands.get(1).and_then(get_op_reg) {
                        let val_t = load_reg(&mut builder, ctx_ptr, rt);
                        let tpidr_off = 784i32;
                        builder.ins().store(MemFlags::trusted(), val_t, ctx_ptr, tpidr_off);
                        compiled_any = true;
                    }
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
