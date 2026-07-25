use crate::{
    cpu::CpuContext,
    decoder::{Decoder, Op, Operand, Reg},
    memory::MemoryManager,
    syscall::SyscallDispatcher,
    Result,
};

pub struct Interpreter;

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

fn imm_to_u64(imm: &bad64::Imm) -> u64 {
    match imm {
        bad64::Imm::Signed(val) => *val as u64,
        bad64::Imm::Unsigned(val) => *val,
    }
}

fn imm_to_i64(imm: &bad64::Imm) -> i64 {
    match imm {
        bad64::Imm::Signed(val) => *val,
        bad64::Imm::Unsigned(val) => *val as i64,
    }
}

fn get_reg_val(reg: Reg, ctx: &CpuContext) -> u64 {
    if let Some(idx) = reg_idx(reg) {
        ctx.get_x(idx)
    } else if reg == Reg::SP {
        ctx.sp
    } else {
        0
    }
}

fn set_reg_val(reg: Reg, val: u64, ctx: &mut CpuContext) {
    if let Some(idx) = reg_idx(reg) {
        ctx.set_x(idx, val);
    } else if reg == Reg::SP {
        ctx.sp = val;
    }
}

fn get_operand_val(op: &Operand, ctx: &CpuContext) -> u64 {
    match op {
        Operand::Reg { reg, .. } => get_reg_val(*reg, ctx),
        Operand::Imm64 { imm, .. } => imm_to_u64(imm),
        Operand::Imm32 { imm, .. } => imm_to_u64(imm),
        Operand::Label(imm) => imm_to_u64(imm),
        _ => 0,
    }
}

fn shift_val(shift: Option<&bad64::Shift>) -> u32 {
    match shift {
        Some(bad64::Shift::LSL(amt)) | Some(bad64::Shift::LSR(amt)) | Some(bad64::Shift::ASR(amt)) | Some(bad64::Shift::ROR(amt)) => *amt as u32,
        _ => 0,
    }
}

fn eval_cond<T: std::fmt::Debug>(cond: &T, ctx: &CpuContext) -> bool {
    let cond_str = format!("{:?}", cond);
    match cond_str.as_str() {
        "EQ" => ctx.get_z(),
        "NE" => !ctx.get_z(),
        "CS" | "HS" => ctx.get_c(),
        "CC" | "LO" => !ctx.get_c(),
        "MI" => ctx.get_n(),
        "PL" => !ctx.get_n(),
        "VS" => ctx.get_v(),
        "VC" => !ctx.get_v(),
        "HI" => ctx.get_c() && !ctx.get_z(),
        "LS" => !ctx.get_c() || ctx.get_z(),
        "GE" => ctx.get_n() == ctx.get_v(),
        "LT" => ctx.get_n() != ctx.get_v(),
        "GT" => !ctx.get_z() && (ctx.get_n() == ctx.get_v()),
        "LE" => ctx.get_z() || (ctx.get_n() != ctx.get_v()),
        _ => true,
    }
}

fn eval_mem_addr(op: &Operand, ctx: &mut CpuContext) -> Option<u64> {
    match op {
        Operand::MemOffset { reg, offset, .. } => {
            let base = get_reg_val(*reg, ctx);
            let off = imm_to_i64(offset);
            Some((base as i64 + off) as u64)
        }
        Operand::MemPreIdx { reg, imm, .. } => {
            let base = get_reg_val(*reg, ctx);
            let off = imm_to_i64(imm);
            let new_addr = (base as i64 + off) as u64;
            set_reg_val(*reg, new_addr, ctx);
            Some(new_addr)
        }
        Operand::MemPostIdxImm { reg, imm, .. } => {
            let base = get_reg_val(*reg, ctx);
            let off = imm_to_i64(imm);
            let new_base = (base as i64 + off) as u64;
            set_reg_val(*reg, new_base, ctx);
            Some(base)
        }
        Operand::Label(imm) => Some(imm_to_u64(imm)),
        _ => None,
    }
}

fn m_err(pc: u64, e: crate::Error) -> crate::Error {
    crate::Error::InterpreterError {
        pc,
        reason: format!("Memory error at PC {:#x}: {}", pc, e),
    }
}

impl Interpreter {
    pub fn step(ctx: &mut CpuContext, mem: &mut MemoryManager) -> Result<bool> {
        if ctx.exited {
            return Ok(false);
        }

        let pc = ctx.pc;
        let ins_bytes = mem.read(pc, 4).map_err(|e| m_err(pc, e))?;
        let ins_u32 = u32::from_le_bytes(ins_bytes.try_into().unwrap());

        let inst = Decoder::decode(ins_u32, pc).map_err(|e| crate::Error::DecodeError {
            pc,
            reason: e.to_string(),
        })?;

        let mut next_pc = pc + 4;

        match inst.op() {
            Op::ADD | Op::ADDS => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    let v1 = get_operand_val(&ops[1], ctx);
                    let v2 = get_operand_val(&ops[2], ctx);
                    let (res, overflow) = v1.overflowing_add(v2);
                    if let Operand::Reg { reg, .. } = ops[0] {
                        set_reg_val(reg, res, ctx);
                    }
                    if inst.op() == Op::ADDS {
                        let n = (res as i64) < 0;
                        let z = res == 0;
                        let c = overflow;
                        let v = ((v1 ^ !v2) & (v1 ^ res) & 0x8000_0000_0000_0000) != 0;
                        ctx.set_nzcv(n, z, c, v);
                    }
                }
            }
            Op::SUB | Op::SUBS | Op::CMP => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    let (op1, op2) = if inst.op() == Op::CMP {
                        (&ops[0], &ops[1])
                    } else if ops.len() >= 3 {
                        (&ops[1], &ops[2])
                    } else {
                        (&ops[0], &ops[1])
                    };
                    let v1 = get_operand_val(op1, ctx);
                    let v2 = get_operand_val(op2, ctx);
                    let (res, borrow) = v1.overflowing_sub(v2);

                    if inst.op() != Op::CMP && ops.len() >= 3 {
                        if let Operand::Reg { reg, .. } = ops[0] {
                            set_reg_val(reg, res, ctx);
                        }
                    }

                    if inst.op() == Op::SUBS || inst.op() == Op::CMP {
                        let n = (res as i64) < 0;
                        let z = res == 0;
                        let c = !borrow;
                        let v = ((v1 ^ v2) & (v1 ^ res) & 0x8000_0000_0000_0000) != 0;
                        ctx.set_nzcv(n, z, c, v);
                    }
                }
            }
            Op::MOV => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        let val = get_operand_val(&ops[1], ctx);
                        set_reg_val(reg, val, ctx);
                    }
                }
            }
            Op::MOVK => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        let imm = get_operand_val(&ops[1], ctx) & 0xffff;
                        let s_val = if let Operand::Imm64 { shift, .. } = ops[1] {
                            shift_val(shift.as_ref())
                        } else if let Operand::Imm32 { shift, .. } = ops[1] {
                            shift_val(shift.as_ref())
                        } else {
                            0
                        };
                        let cur_val = get_reg_val(reg, ctx);
                        let mask = !(0xffffu64 << s_val);
                        let new_val = (cur_val & mask) | (imm << s_val);
                        set_reg_val(reg, new_val, ctx);
                    }
                }
            }
            Op::MOVN => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        let imm = get_operand_val(&ops[1], ctx) & 0xffff;
                        let s_val = if let Operand::Imm64 { shift, .. } = ops[1] {
                            shift_val(shift.as_ref())
                        } else if let Operand::Imm32 { shift, .. } = ops[1] {
                            shift_val(shift.as_ref())
                        } else {
                            0
                        };
                        let val = !(imm << s_val);
                        set_reg_val(reg, val, ctx);
                    }
                }
            }
            Op::ADRP => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        let target_addr = get_operand_val(&ops[1], ctx);
                        set_reg_val(reg, target_addr & !0xfff, ctx);
                    }
                }
            }
            Op::B => {
                let ops = inst.operands();
                if !ops.is_empty() {
                    let target_addr = get_operand_val(&ops[0], ctx);
                    next_pc = target_addr;
                }
            }
            Op::B_EQ | Op::B_NE | Op::B_CS | Op::B_CC | Op::B_MI | Op::B_PL | Op::B_VS | Op::B_VC | Op::B_HI | Op::B_LS | Op::B_GE | Op::B_LT | Op::B_GT | Op::B_LE => {
                let ops = inst.operands();
                if !ops.is_empty() {
                    let cond_holds = match inst.op() {
                        Op::B_EQ => ctx.get_z(),
                        Op::B_NE => !ctx.get_z(),
                        Op::B_CS => ctx.get_c(),
                        Op::B_CC => !ctx.get_c(),
                        Op::B_MI => ctx.get_n(),
                        Op::B_PL => !ctx.get_n(),
                        Op::B_VS => ctx.get_v(),
                        Op::B_VC => !ctx.get_v(),
                        Op::B_HI => ctx.get_c() && !ctx.get_z(),
                        Op::B_LS => !ctx.get_c() || ctx.get_z(),
                        Op::B_GE => ctx.get_n() == ctx.get_v(),
                        Op::B_LT => ctx.get_n() != ctx.get_v(),
                        Op::B_GT => !ctx.get_z() && (ctx.get_n() == ctx.get_v()),
                        Op::B_LE => ctx.get_z() || (ctx.get_n() != ctx.get_v()),
                        _ => false,
                    };
                    if cond_holds {
                        let target_addr = get_operand_val(&ops[0], ctx);
                        next_pc = target_addr;
                    }
                }
            }
            Op::CBZ | Op::CBNZ => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    let reg_val = get_operand_val(&ops[0], ctx);
                    let is_zero = reg_val == 0;
                    let should_branch = match inst.op() {
                        Op::CBZ => is_zero,
                        Op::CBNZ => !is_zero,
                        _ => false,
                    };
                    if should_branch {
                        let target_addr = get_operand_val(&ops[1], ctx);
                        next_pc = target_addr;
                    }
                }
            }
            Op::BL => {
                let ops = inst.operands();
                if !ops.is_empty() {
                    ctx.set_x(30, pc + 4);
                    let target_addr = get_operand_val(&ops[0], ctx);
                    next_pc = target_addr;
                }
            }
            Op::RET => {
                let ret_addr = ctx.get_x(30);
                next_pc = ret_addr;
            }
            Op::LDR | Op::LDUR => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        if let Some(addr) = eval_mem_addr(&ops[1], ctx) {
                            let val_bytes = mem.read(addr, 8).map_err(|e| m_err(pc, e))?;
                            let val = u64::from_le_bytes(val_bytes.try_into().unwrap());
                            set_reg_val(reg, val, ctx);
                        }
                    }
                }
            }
            Op::LDRH => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        if let Some(addr) = eval_mem_addr(&ops[1], ctx) {
                            let val_bytes = mem.read(addr, 2).map_err(|e| m_err(pc, e))?;
                            let val = u16::from_le_bytes(val_bytes.try_into().unwrap()) as u64;
                            set_reg_val(reg, val, ctx);
                        }
                    }
                }
            }
            Op::LDRSH => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        if let Some(addr) = eval_mem_addr(&ops[1], ctx) {
                            let val_bytes = mem.read(addr, 2).map_err(|e| m_err(pc, e))?;
                            let val = i16::from_le_bytes(val_bytes.try_into().unwrap()) as i64 as u64;
                            set_reg_val(reg, val, ctx);
                        }
                    }
                }
            }
            Op::STR | Op::STUR => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    let val = get_operand_val(&ops[0], ctx);
                    if let Some(addr) = eval_mem_addr(&ops[1], ctx) {
                        mem.write(addr, &val.to_le_bytes()).map_err(|e| m_err(pc, e))?;
                    }
                }
            }
            Op::STRH => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    let val = get_operand_val(&ops[0], ctx) as u16;
                    if let Some(addr) = eval_mem_addr(&ops[1], ctx) {
                        mem.write(addr, &val.to_le_bytes()).map_err(|e| m_err(pc, e))?;
                    }
                }
            }
            Op::STP => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    let v1 = get_operand_val(&ops[0], ctx);
                    let v2 = get_operand_val(&ops[1], ctx);
                    if let Some(addr) = eval_mem_addr(&ops[2], ctx) {
                        mem.write(addr, &v1.to_le_bytes()).map_err(|e| m_err(pc, e))?;
                        mem.write(addr + 8, &v2.to_le_bytes()).map_err(|e| m_err(pc, e))?;
                    }
                }
            }
            Op::LDP => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    if let (Operand::Reg { reg: r1, .. }, Operand::Reg { reg: r2, .. }) = (&ops[0], &ops[1]) {
                        if let Some(addr) = eval_mem_addr(&ops[2], ctx) {
                            let b1 = mem.read(addr, 8).map_err(|e| m_err(pc, e))?;
                            let v1 = u64::from_le_bytes(b1.try_into().unwrap());
                            let b2 = mem.read(addr + 8, 8).map_err(|e| m_err(pc, e))?;
                            let v2 = u64::from_le_bytes(b2.try_into().unwrap());
                            set_reg_val(*r1, v1, ctx);
                            set_reg_val(*r2, v2, ctx);
                        }
                    }
                }
            }
            Op::LDRB => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        if let Some(addr) = eval_mem_addr(&ops[1], ctx) {
                            let b = mem.read(addr, 1).map_err(|e| m_err(pc, e))?;
                            set_reg_val(reg, b[0] as u64, ctx);
                        }
                    }
                }
            }
            Op::LDRSB => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        if let Some(addr) = eval_mem_addr(&ops[1], ctx) {
                            let b = mem.read(addr, 1).map_err(|e| m_err(pc, e))?;
                            let val = (b[0] as i8) as i64 as u64;
                            set_reg_val(reg, val, ctx);
                        }
                    }
                }
            }
            Op::STRB => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    let val = get_operand_val(&ops[0], ctx) as u8;
                    if let Some(addr) = eval_mem_addr(&ops[1], ctx) {
                        mem.write(addr, &[val]).map_err(|e| m_err(pc, e))?;
                    }
                }
            }
            Op::CSEL | Op::CSINC | Op::CSINV | Op::CSNEG => {
                let ops = inst.operands();
                if ops.len() >= 4 {
                    if let (Operand::Reg { reg: rd, .. }, Operand::Cond(cond)) = (ops[0], ops[3]) {
                        let v1 = get_operand_val(&ops[1], ctx);
                        let v2 = get_operand_val(&ops[2], ctx);
                        let cond_holds = eval_cond(&cond, ctx);
                        let res = if cond_holds {
                            v1
                        } else {
                            match inst.op() {
                                Op::CSINC => v2.wrapping_add(1),
                                Op::CSINV => !v2,
                                Op::CSNEG => (-(v2 as i64)) as u64,
                                _ => v2,
                            }
                        };
                        set_reg_val(rd, res, ctx);
                    }
                }
            }
            Op::CCMP | Op::CCMN => {
                let ops = inst.operands();
                if ops.len() >= 4 {
                    if let Operand::Cond(cond) = ops[3] {
                        let cond_holds = eval_cond(&cond, ctx);
                        if cond_holds {
                            let v1 = get_operand_val(&ops[0], ctx);
                            let v2 = get_operand_val(&ops[1], ctx);
                            let (res, borrow) = v1.overflowing_sub(v2);
                            let n = (res as i64) < 0;
                            let z = res == 0;
                            let c = !borrow;
                            let v = ((v1 ^ v2) & (v1 ^ res) & 0x8000_0000_0000_0000) != 0;
                            ctx.set_nzcv(n, z, c, v);
                        } else {
                            let flags_raw = get_operand_val(&ops[2], ctx) as u32;
                            let n = (flags_raw & 8) != 0;
                            let z = (flags_raw & 4) != 0;
                            let c = (flags_raw & 2) != 0;
                            let v = (flags_raw & 1) != 0;
                            ctx.set_nzcv(n, z, c, v);
                        }
                    }
                }
            }
            Op::MRS => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        set_reg_val(reg, ctx.tpidr_el0, ctx);
                    }
                }
            }
            Op::MSR => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    let val = get_operand_val(&ops[1], ctx);
                    ctx.tpidr_el0 = val;
                }
            }
            Op::ORR => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        let v1 = get_operand_val(&ops[1], ctx);
                        let v2 = get_operand_val(&ops[2], ctx);
                        set_reg_val(reg, v1 | v2, ctx);
                    }
                }
            }
            Op::EOR => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        let v1 = get_operand_val(&ops[1], ctx);
                        let v2 = get_operand_val(&ops[2], ctx);
                        set_reg_val(reg, v1 ^ v2, ctx);
                    }
                }
            }
            Op::AND => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        let v1 = get_operand_val(&ops[1], ctx);
                        let v2 = get_operand_val(&ops[2], ctx);
                        set_reg_val(reg, v1 & v2, ctx);
                    }
                }
            }
            Op::NOP => {
                // Do nothing
            }
            Op::SVC => {
                SyscallDispatcher::handle_syscall(ctx, mem)?;
                if ctx.exited {
                    return Ok(false);
                }
            }
            _ => {
                return Err(crate::Error::InterpreterError {
                    pc,
                    reason: format!("Unimplemented opcode {:?}", inst.op()),
                });
            }
        }

        ctx.pc = next_pc;
        Ok(true)
    }

    pub fn run(ctx: &mut CpuContext, mem: &mut MemoryManager) -> Result<()> {
        while Interpreter::step(ctx, mem)? {}
        Ok(())
    }

    pub fn run_max_steps(ctx: &mut CpuContext, mem: &mut MemoryManager, max_steps: usize) -> Result<bool> {
        let mut steps = 0;
        while steps < max_steps {
            if !Interpreter::step(ctx, mem)? {
                return Ok(true); // Exited cleanly
            }
            steps += 1;
        }
        Ok(false) // Limit reached
    }
}
