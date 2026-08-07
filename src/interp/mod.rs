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

fn is_w_reg(reg: Reg) -> bool {
    matches!(
        reg,
        Reg::W0 | Reg::W1 | Reg::W2 | Reg::W3 | Reg::W4 | Reg::W5 | Reg::W6 | Reg::W7 |
        Reg::W8 | Reg::W9 | Reg::W10 | Reg::W11 | Reg::W12 | Reg::W13 | Reg::W14 | Reg::W15 |
        Reg::W16 | Reg::W17 | Reg::W18 | Reg::W19 | Reg::W20 | Reg::W21 | Reg::W22 | Reg::W23 |
        Reg::W24 | Reg::W25 | Reg::W26 | Reg::W27 | Reg::W28 | Reg::W29 | Reg::W30 | Reg::WZR
    )
}

fn is_d_reg(reg: Reg) -> bool {
    matches!(
        reg,
        Reg::D0 | Reg::D1 | Reg::D2 | Reg::D3 | Reg::D4 | Reg::D5 | Reg::D6 | Reg::D7 |
        Reg::D8 | Reg::D9 | Reg::D10 | Reg::D11 | Reg::D12 | Reg::D13 | Reg::D14 | Reg::D15 |
        Reg::D16 | Reg::D17 | Reg::D18 | Reg::D19 | Reg::D20 | Reg::D21 | Reg::D22 | Reg::D23 |
        Reg::D24 | Reg::D25 | Reg::D26 | Reg::D27 | Reg::D28 | Reg::D29 | Reg::D30 | Reg::D31
    )
}

fn is_s_reg(reg: Reg) -> bool {
    matches!(
        reg,
        Reg::S0 | Reg::S1 | Reg::S2 | Reg::S3 | Reg::S4 | Reg::S5 | Reg::S6 | Reg::S7 |
        Reg::S8 | Reg::S9 | Reg::S10 | Reg::S11 | Reg::S12 | Reg::S13 | Reg::S14 | Reg::S15 |
        Reg::S16 | Reg::S17 | Reg::S18 | Reg::S19 | Reg::S20 | Reg::S21 | Reg::S22 | Reg::S23 |
        Reg::S24 | Reg::S25 | Reg::S26 | Reg::S27 | Reg::S28 | Reg::S29 | Reg::S30 | Reg::S31
    )
}

fn is_64bit_vector(op: &Operand) -> bool {
    let s = format!("{:?}", op);
    s.contains("8B") || s.contains("4H") || s.contains("2S") || s.contains("1D") || s.contains("8b") || s.contains("4h") || s.contains("2s") || s.contains("1d")
}

fn get_vec_elem_size(op: &Operand) -> usize {
    let s = format!("{:?}", op);
    if s.contains("16B") || s.contains("8B") || s.contains("16b") || s.contains("8b") {
        1
    } else if s.contains("8H") || s.contains("4H") || s.contains("8h") || s.contains("4h") {
        2
    } else if s.contains("4S") || s.contains("2S") || s.contains("4s") || s.contains("2s") {
        4
    } else if s.contains("2D") || s.contains("1D") || s.contains("2d") || s.contains("1d") {
        8
    } else {
        1
    }
}

fn v_reg_idx(reg: Reg) -> Option<usize> {
    match reg {
        Reg::B0 | Reg::H0 | Reg::S0 | Reg::D0 | Reg::Q0 | Reg::V0 => Some(0),
        Reg::B1 | Reg::H1 | Reg::S1 | Reg::D1 | Reg::Q1 | Reg::V1 => Some(1),
        Reg::B2 | Reg::H2 | Reg::S2 | Reg::D2 | Reg::Q2 | Reg::V2 => Some(2),
        Reg::B3 | Reg::H3 | Reg::S3 | Reg::D3 | Reg::Q3 | Reg::V3 => Some(3),
        Reg::B4 | Reg::H4 | Reg::S4 | Reg::D4 | Reg::Q4 | Reg::V4 => Some(4),
        Reg::B5 | Reg::H5 | Reg::S5 | Reg::D5 | Reg::Q5 | Reg::V5 => Some(5),
        Reg::B6 | Reg::H6 | Reg::S6 | Reg::D6 | Reg::Q6 | Reg::V6 => Some(6),
        Reg::B7 | Reg::H7 | Reg::S7 | Reg::D7 | Reg::Q7 | Reg::V7 => Some(7),
        Reg::B8 | Reg::H8 | Reg::S8 | Reg::D8 | Reg::Q8 | Reg::V8 => Some(8),
        Reg::B9 | Reg::H9 | Reg::S9 | Reg::D9 | Reg::Q9 | Reg::V9 => Some(9),
        Reg::B10 | Reg::H10 | Reg::S10 | Reg::D10 | Reg::Q10 | Reg::V10 => Some(10),
        Reg::B11 | Reg::H11 | Reg::S11 | Reg::D11 | Reg::Q11 | Reg::V11 => Some(11),
        Reg::B12 | Reg::H12 | Reg::S12 | Reg::D12 | Reg::Q12 | Reg::V12 => Some(12),
        Reg::B13 | Reg::H13 | Reg::S13 | Reg::D13 | Reg::Q13 | Reg::V13 => Some(13),
        Reg::B14 | Reg::H14 | Reg::S14 | Reg::D14 | Reg::Q14 | Reg::V14 => Some(14),
        Reg::B15 | Reg::H15 | Reg::S15 | Reg::D15 | Reg::Q15 | Reg::V15 => Some(15),
        Reg::B16 | Reg::H16 | Reg::S16 | Reg::D16 | Reg::Q16 | Reg::V16 => Some(16),
        Reg::B17 | Reg::H17 | Reg::S17 | Reg::D17 | Reg::Q17 | Reg::V17 => Some(17),
        Reg::B18 | Reg::H18 | Reg::S18 | Reg::D18 | Reg::Q18 | Reg::V18 => Some(18),
        Reg::B19 | Reg::H19 | Reg::S19 | Reg::D19 | Reg::Q19 | Reg::V19 => Some(19),
        Reg::B20 | Reg::H20 | Reg::S20 | Reg::D20 | Reg::Q20 | Reg::V20 => Some(20),
        Reg::B21 | Reg::H21 | Reg::S21 | Reg::D21 | Reg::Q21 | Reg::V21 => Some(21),
        Reg::B22 | Reg::H22 | Reg::S22 | Reg::D22 | Reg::Q22 | Reg::V22 => Some(22),
        Reg::B23 | Reg::H23 | Reg::S23 | Reg::D23 | Reg::Q23 | Reg::V23 => Some(23),
        Reg::B24 | Reg::H24 | Reg::S24 | Reg::D24 | Reg::Q24 | Reg::V24 => Some(24),
        Reg::B25 | Reg::H25 | Reg::S25 | Reg::D25 | Reg::Q25 | Reg::V25 => Some(25),
        Reg::B26 | Reg::H26 | Reg::S26 | Reg::D26 | Reg::Q26 | Reg::V26 => Some(26),
        Reg::B27 | Reg::H27 | Reg::S27 | Reg::D27 | Reg::Q27 | Reg::V27 => Some(27),
        Reg::B28 | Reg::H28 | Reg::S28 | Reg::D28 | Reg::Q28 | Reg::V28 => Some(28),
        Reg::B29 | Reg::H29 | Reg::S29 | Reg::D29 | Reg::Q29 | Reg::V29 => Some(29),
        Reg::B30 | Reg::H30 | Reg::S30 | Reg::D30 | Reg::Q30 | Reg::V30 => Some(30),
        Reg::B31 | Reg::H31 | Reg::S31 | Reg::D31 | Reg::Q31 | Reg::V31 => Some(31),
        _ => None,
    }
}

fn reg_size(reg: Reg) -> usize {
    let s = format!("{:?}", reg);
    if s.starts_with('Q') || s.starts_with('V') {
        16
    } else if s.starts_with('D') || s.starts_with('X') {
        8
    } else if s.starts_with('S') || s.starts_with('W') {
        4
    } else if s.starts_with('H') {
        2
    } else if s.starts_with('B') {
        1
    } else {
        8
    }
}

fn get_reg_val(reg: Reg, ctx: &CpuContext) -> u64 {
    if is_w_reg(reg) {
        if let Some(idx) = reg_idx(reg) {
            ctx.get_x(idx) & 0xFFFF_FFFF
        } else {
            0
        }
    } else if let Some(idx) = reg_idx(reg) {
        ctx.get_x(idx)
    } else if let Some(idx) = v_reg_idx(reg) {
        let sz = reg_size(reg);
        let mut buf = [0u8; 8];
        let copy_sz = sz.min(8);
        buf[..copy_sz].copy_from_slice(&ctx.v[idx][..copy_sz]);
        u64::from_le_bytes(buf)
    } else if reg == Reg::SP {
        ctx.sp
    } else {
        0
    }
}

fn set_reg_val(reg: Reg, val: u64, ctx: &mut CpuContext) {
    if is_w_reg(reg) {
        if let Some(idx) = reg_idx(reg) {
            ctx.set_x(idx, val & 0xFFFF_FFFF);
        }
    } else if let Some(idx) = reg_idx(reg) {
        ctx.set_x(idx, val);
    } else if let Some(idx) = v_reg_idx(reg) {
        let sz = reg_size(reg);
        let copy_sz = sz.min(8);
        ctx.v[idx] = [0u8; 16];
        ctx.v[idx][..copy_sz].copy_from_slice(&val.to_le_bytes()[..copy_sz]);
    } else if reg == Reg::SP {
        ctx.sp = val;
    }
}

fn eval_shift_reg(reg: Reg, shift: &bad64::Shift, ctx: &CpuContext) -> u64 {
    let raw = get_reg_val(reg, ctx);
    let is_32 = is_w_reg(reg);
    match shift {
        bad64::Shift::LSL(amt) => {
            let a = amt & (if is_32 { 31 } else { 63 });
            if is_32 { ((raw as u32).wrapping_shl(a)) as u64 } else { raw.wrapping_shl(a) }
        }
        bad64::Shift::LSR(amt) => {
            let a = amt & (if is_32 { 31 } else { 63 });
            if is_32 { ((raw as u32).wrapping_shr(a)) as u64 } else { raw.wrapping_shr(a) }
        }
        bad64::Shift::ASR(amt) => {
            let a = amt & (if is_32 { 31 } else { 63 });
            if is_32 { (((raw as u32 as i32).wrapping_shr(a)) as u32) as u64 } else { ((raw as i64).wrapping_shr(a)) as u64 }
        }
        bad64::Shift::ROR(amt) => {
            let a = amt & (if is_32 { 31 } else { 63 });
            if is_32 { ((raw as u32).rotate_right(a)) as u64 } else { raw.rotate_right(a) }
        }
        bad64::Shift::UXTB(amt) => ((raw as u8) as u64) << (amt & 63),
        bad64::Shift::UXTH(amt) => ((raw as u16) as u64) << (amt & 63),
        bad64::Shift::UXTW(amt) => ((raw as u32) as u64) << (amt & 63),
        bad64::Shift::UXTX(amt) => raw << (amt & 63),
        bad64::Shift::SXTB(amt) => (((raw as i8) as i64) as u64) << (amt & 63),
        bad64::Shift::SXTH(amt) => (((raw as i16) as i64) as u64) << (amt & 63),
        bad64::Shift::SXTW(amt) => (((raw as i32) as i64) as u64) << (amt & 63),
        bad64::Shift::SXTX(amt) => raw << (amt & 63),
        bad64::Shift::MSL(amt) => (raw << (amt & 63)) | ((1u64 << (amt & 63)) - 1),
    }
}

fn get_op_reg(op: &Operand) -> Option<Reg> {
    match op {
        Operand::Reg { reg, .. } => Some(*reg),
        Operand::QualReg { reg, .. } => Some(*reg),
        Operand::ShiftReg { reg, .. } => Some(*reg),
        Operand::MultiReg { regs, .. } => regs.iter().find_map(|r| *r),
        _ => None,
    }
}

#[allow(dead_code)]
fn get_multi_regs(op: &Operand) -> Vec<Reg> {
    match op {
        Operand::MultiReg { regs, .. } => regs.iter().filter_map(|r| *r).collect(),
        _ => get_op_reg(op).into_iter().collect(),
    }
}

fn eval_imm_shift(raw_val: u64, shift: Option<&bad64::Shift>) -> u64 {
    if let Some(s) = shift {
        match s {
            bad64::Shift::LSL(amt) => raw_val.wrapping_shl(*amt as u32),
            bad64::Shift::LSR(amt) => raw_val.wrapping_shr(*amt as u32),
            bad64::Shift::ASR(amt) => ((raw_val as i64).wrapping_shr(*amt as u32)) as u64,
            bad64::Shift::ROR(amt) => raw_val.rotate_right(*amt as u32),
            _ => raw_val,
        }
    } else {
        raw_val
    }
}

fn get_operand_val(op: &Operand, ctx: &CpuContext) -> u64 {
    match op {
        Operand::Reg { reg, .. } => get_reg_val(*reg, ctx),
        Operand::QualReg { reg, .. } => get_reg_val(*reg, ctx),
        Operand::ShiftReg { reg, shift, .. } => eval_shift_reg(*reg, shift, ctx),
        Operand::Imm64 { imm, shift } => eval_imm_shift(imm_to_u64(imm), shift.as_ref()),
        Operand::Imm32 { imm, shift } => eval_imm_shift(imm_to_u64(imm), shift.as_ref()),
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
    let cond_str = format!("{:?}", cond).to_uppercase();
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
        Operand::Reg { reg, .. } | Operand::QualReg { reg, .. } | Operand::MemReg(reg) => {
            Some(get_reg_val(*reg, ctx))
        }
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
        Operand::MemExt { regs, shift, .. } => {
            let base = get_reg_val(regs[0], ctx);
            let off = if let Some(s) = shift {
                eval_shift_reg(regs[1], s, ctx)
            } else if is_w_reg(regs[1]) {
                (get_reg_val(regs[1], ctx) as u32) as u64
            } else {
                get_reg_val(regs[1], ctx)
            };
            Some(base.wrapping_add(off))
        }
        Operand::MemPostIdxReg(regs) => {
            let base = get_reg_val(regs[0], ctx);
            let off = get_reg_val(regs[1], ctx);
            set_reg_val(regs[0], base.wrapping_add(off), ctx);
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



        // Handle DC ZVA (0xd50b7400 | Rt)
        if (ins_u32 & 0xfffffe00) == 0xd50b7400 {
            let rt = (ins_u32 & 0x1f) as usize;
            let addr = ctx.get_x(rt) & !63;
            let zeros = [0u8; 64];
            let _ = mem.write(addr, &zeros);
            ctx.pc = pc + 4;
            return Ok(true);
        }

        let inst = match Decoder::decode(ins_u32, pc) {
            Ok(i) => i,
            Err(e) => {
                // ARM System Hint space (0xd5032xxx): NOP
                if (ins_u32 & 0xfffff01f) == 0xd503201f || (ins_u32 & 0xfff00000) == 0xd5000000 {
                    ctx.pc = pc + 4;
                    return Ok(true);
                }
                return Err(crate::Error::DecodeError {
                    pc,
                    reason: e.to_string(),
                });
            }
        };

        let mut next_pc = pc + 4;

        match inst.op() {
            Op::ADD | Op::ADDS | Op::CMN => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    let target_reg = if inst.op() == Op::CMN {
                        None
                    } else if ops.len() >= 3 {
                        get_op_reg(&ops[0])
                    } else {
                        get_op_reg(&ops[0])
                    };

                    if let Some(reg) = target_reg {
                        if let Some(idx0) = v_reg_idx(reg) {
                            let op_count = ops.len();
                            let vec1 = ops.get(if op_count >= 3 { op_count - 2 } else { 0 }).and_then(get_op_reg).and_then(v_reg_idx).map(|idx| ctx.v[idx]).unwrap_or([0u8; 16]);
                            let vec2 = ops.get(op_count - 1).and_then(get_op_reg).and_then(v_reg_idx).map(|idx| ctx.v[idx]).unwrap_or([0u8; 16]);
                            let elem_sz = get_vec_elem_size(&ops[0]);
                            let mut res = [0u8; 16];
                            let num_elems = 16 / elem_sz;
                            for i in 0..num_elems {
                                match elem_sz {
                                    1 => res[i] = vec1[i].wrapping_add(vec2[i]),
                                    2 => {
                                        let a = u16::from_le_bytes([vec1[i * 2], vec1[i * 2 + 1]]);
                                        let b = u16::from_le_bytes([vec2[i * 2], vec2[i * 2 + 1]]);
                                        res[i * 2..i * 2 + 2].copy_from_slice(&a.wrapping_add(b).to_le_bytes());
                                    }
                                    4 => {
                                        let a = u32::from_le_bytes(vec1[i * 4..i * 4 + 4].try_into().unwrap());
                                        let b = u32::from_le_bytes(vec2[i * 4..i * 4 + 4].try_into().unwrap());
                                        res[i * 4..i * 4 + 4].copy_from_slice(&a.wrapping_add(b).to_le_bytes());
                                    }
                                    _ => {
                                        let a = u64::from_le_bytes(vec1[i * 8..i * 8 + 8].try_into().unwrap());
                                        let b = u64::from_le_bytes(vec2[i * 8..i * 8 + 8].try_into().unwrap());
                                        res[i * 8..i * 8 + 8].copy_from_slice(&a.wrapping_add(b).to_le_bytes());
                                    }
                                }
                            }
                            ctx.v[idx0] = res;
                        } else {
                            let (op1, op2) = if inst.op() == Op::CMN {
                                (&ops[0], &ops[1])
                            } else if ops.len() >= 3 {
                                (&ops[1], &ops[2])
                            } else {
                                (&ops[0], &ops[1])
                            };
                            let v1 = get_operand_val(op1, ctx);
                            let v2 = get_operand_val(op2, ctx);
                            let (res, overflow) = v1.overflowing_add(v2);
                            set_reg_val(reg, res, ctx);

                            if inst.op() == Op::ADDS || inst.op() == Op::CMN {
                                let is_32 = get_op_reg(op1).map(is_w_reg).unwrap_or(false);
                                if is_32 {
                                    let v1_32 = v1 as u32;
                                    let v2_32 = v2 as u32;
                                    let (r32, overflow_32) = v1_32.overflowing_add(v2_32);
                                    let n = (r32 as i32) < 0;
                                    let z = r32 == 0;
                                    let c = overflow_32;
                                    let v = ((v1_32 ^ !v2_32) & (v1_32 ^ r32) & 0x8000_0000) != 0;
                                    ctx.set_nzcv(n, z, c, v);
                                } else {
                                    let n = (res as i64) < 0;
                                    let z = res == 0;
                                    let c = overflow;
                                    let v = ((v1 ^ !v2) & (v1 ^ res) & 0x8000_0000_0000_0000) != 0;
                                    ctx.set_nzcv(n, z, c, v);
                                }
                            }
                        }
                    } else if inst.op() == Op::CMN {
                        let (op1, op2) = (&ops[0], &ops[1]);
                        let v1 = get_operand_val(op1, ctx);
                        let v2 = get_operand_val(op2, ctx);
                        let (res, overflow) = v1.overflowing_add(v2);
                        let is_32 = get_op_reg(op1).map(is_w_reg).unwrap_or(false);
                        if is_32 {
                            let v1_32 = v1 as u32;
                            let v2_32 = v2 as u32;
                            let (r32, overflow_32) = v1_32.overflowing_add(v2_32);
                            let n = (r32 as i32) < 0;
                            let z = r32 == 0;
                            let c = overflow_32;
                            let v = ((v1_32 ^ !v2_32) & (v1_32 ^ r32) & 0x8000_0000) != 0;
                            ctx.set_nzcv(n, z, c, v);
                        } else {
                            let n = (res as i64) < 0;
                            let z = res == 0;
                            let c = overflow;
                            let v = ((v1 ^ !v2) & (v1 ^ res) & 0x8000_0000_0000_0000) != 0;
                            ctx.set_nzcv(n, z, c, v);
                        }
                    }
                }
            }
            Op::SUB | Op::SUBS | Op::CMP => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    let (target_reg, op1, op2) = if inst.op() == Op::CMP {
                        (None, &ops[0], &ops[1])
                    } else if ops.len() >= 3 {
                        (get_op_reg(&ops[0]), &ops[1], &ops[2])
                    } else {
                        (get_op_reg(&ops[0]), &ops[0], &ops[1])
                    };
                    let v1 = get_operand_val(op1, ctx);
                    let v2 = get_operand_val(op2, ctx);
                    let (res, borrow) = v1.overflowing_sub(v2);

                    if let Some(reg) = target_reg {
                        set_reg_val(reg, res, ctx);
                    }

                    if inst.op() == Op::SUBS || inst.op() == Op::CMP {
                        let is_32 = get_op_reg(op1).map(is_w_reg).unwrap_or(false);
                        if is_32 {
                            let v1_32 = v1 as u32;
                            let v2_32 = v2 as u32;
                            let (r32, borrow_32) = v1_32.overflowing_sub(v2_32);
                            let n = (r32 as i32) < 0;
                            let z = r32 == 0;
                            let c = !borrow_32;
                            let v = ((v1_32 ^ v2_32) & (v1_32 ^ r32) & 0x8000_0000) != 0;
                            ctx.set_nzcv(n, z, c, v);
                        } else {
                            let n = (res as i64) < 0;
                            let z = res == 0;
                            let c = !borrow;
                            let v = ((v1 ^ v2) & (v1 ^ res) & 0x8000_0000_0000_0000) != 0;
                            ctx.set_nzcv(n, z, c, v);
                        }
                    }
                }
            }
            Op::NEG | Op::NEGS => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        let v2 = get_operand_val(&ops[1], ctx);
                        let (res, borrow) = 0u64.overflowing_sub(v2);
                        set_reg_val(reg, res, ctx);
                        if inst.op() == Op::NEGS {
                            let is_32 = is_w_reg(reg);
                            if is_32 {
                                let v2_32 = v2 as u32;
                                let (r32_res, borrow_32) = 0u32.overflowing_sub(v2_32);
                                let n = (r32_res as i32) < 0;
                                let z = r32_res == 0;
                                let c = !borrow_32;
                                let v = ((0 ^ v2_32) & (0 ^ r32_res) & 0x8000_0000) != 0;
                                ctx.set_nzcv(n, z, c, v);
                            } else {
                                let n = (res as i64) < 0;
                                let z = res == 0;
                                let c = !borrow;
                                let v = ((0 ^ v2) & (0 ^ res) & 0x8000_0000_0000_0000) != 0;
                                ctx.set_nzcv(n, z, c, v);
                            }
                        }
                    }
                }
            }
            Op::MOV | Op::MOVI => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        let val = get_operand_val(&ops[1], ctx);
                        if let Some(idx) = v_reg_idx(reg) {
                            let elem_sz = get_vec_elem_size(&ops[0]);
                            let num_elems = 16 / elem_sz;
                            let mut res = [0u8; 16];
                            for i in 0..num_elems {
                                match elem_sz {
                                    1 => res[i] = (val & 0xff) as u8,
                                    2 => res[i*2..i*2+2].copy_from_slice(&((val & 0xffff) as u16).to_le_bytes()),
                                    4 => res[i*4..i*4+4].copy_from_slice(&((val & 0xffffffff) as u32).to_le_bytes()),
                                    _ => res[i*8..i*8+8].copy_from_slice(&val.to_le_bytes()),
                                }
                            }
                            ctx.v[idx] = res;
                        } else {
                            set_reg_val(reg, val, ctx);
                        }
                    }
                }
            }
            Op::MOVK => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        let (raw_imm, shift_opt) = match &ops[1] {
                            Operand::Imm64 { imm, shift } => (imm_to_u64(imm), shift.as_ref()),
                            Operand::Imm32 { imm, shift } => (imm_to_u64(imm), shift.as_ref()),
                            _ => (get_operand_val(&ops[1], ctx), None),
                        };
                        let imm = raw_imm & 0xffff;
                        let s_val = shift_val(shift_opt);
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
            Op::MOVZ => {
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
                        let val = imm << s_val;
                        set_reg_val(reg, val, ctx);
                    }
                }
            }
            Op::UDIV => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        let is_32 = is_w_reg(reg);
                        let v1 = if is_32 { (get_operand_val(&ops[1], ctx) as u32) as u64 } else { get_operand_val(&ops[1], ctx) };
                        let v2 = if is_32 { (get_operand_val(&ops[2], ctx) as u32) as u64 } else { get_operand_val(&ops[2], ctx) };
                        let res = if v2 == 0 { 0 } else { v1 / v2 };
                        set_reg_val(reg, res, ctx);
                    }
                }
            }
            Op::SDIV => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        let is_32 = is_w_reg(reg);
                        let res = if is_32 {
                            let v1 = get_operand_val(&ops[1], ctx) as i32;
                            let v2 = get_operand_val(&ops[2], ctx) as i32;
                            if v2 == 0 { 0 } else { (v1 / v2) as u32 as u64 }
                        } else {
                            let v1 = get_operand_val(&ops[1], ctx) as i64;
                            let v2 = get_operand_val(&ops[2], ctx) as i64;
                            if v2 == 0 { 0 } else { (v1 / v2) as u64 }
                        };
                        set_reg_val(reg, res, ctx);
                    }
                }
            }
            Op::MUL => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        let v1 = get_operand_val(&ops[1], ctx);
                        let v2 = get_operand_val(&ops[2], ctx);
                        set_reg_val(reg, v1.wrapping_mul(v2), ctx);
                    }
                }
            }
            Op::UMULH => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    if let Some(rd) = get_op_reg(&ops[0]) {
                        let v1 = get_operand_val(&ops[1], ctx);
                        let v2 = get_operand_val(&ops[2], ctx);
                        let prod = (v1 as u128) * (v2 as u128);
                        let res = (prod >> 64) as u64;
                        set_reg_val(rd, res, ctx);
                    }
                }
            }
            Op::SMULH => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    if let Some(rd) = get_op_reg(&ops[0]) {
                        let v1 = get_operand_val(&ops[1], ctx) as i64;
                        let v2 = get_operand_val(&ops[2], ctx) as i64;
                        let prod = (v1 as i128) * (v2 as i128);
                        let res = (prod >> 64) as u64;
                        set_reg_val(rd, res, ctx);
                    }
                }
            }
            Op::MADD => {
                let ops = inst.operands();
                if ops.len() >= 4 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        let is_32 = is_w_reg(reg);
                        let v1 = if is_32 { (get_operand_val(&ops[1], ctx) as u32) as u64 } else { get_operand_val(&ops[1], ctx) };
                        let v2 = if is_32 { (get_operand_val(&ops[2], ctx) as u32) as u64 } else { get_operand_val(&ops[2], ctx) };
                        let v3 = if is_32 { (get_operand_val(&ops[3], ctx) as u32) as u64 } else { get_operand_val(&ops[3], ctx) };
                        set_reg_val(reg, v3.wrapping_add(v1.wrapping_mul(v2)), ctx);
                    }
                }
            }
            Op::MSUB => {
                let ops = inst.operands();
                if ops.len() >= 4 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        let is_32 = is_w_reg(reg);
                        let v1 = if is_32 { (get_operand_val(&ops[1], ctx) as u32) as u64 } else { get_operand_val(&ops[1], ctx) };
                        let v2 = if is_32 { (get_operand_val(&ops[2], ctx) as u32) as u64 } else { get_operand_val(&ops[2], ctx) };
                        let v3 = if is_32 { (get_operand_val(&ops[3], ctx) as u32) as u64 } else { get_operand_val(&ops[3], ctx) };
                        set_reg_val(reg, v3.wrapping_sub(v1.wrapping_mul(v2)), ctx);
                    }
                }
            }
            Op::MNEG => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        let is_32 = is_w_reg(reg);
                        let v1 = if is_32 { (get_operand_val(&ops[1], ctx) as u32) as u64 } else { get_operand_val(&ops[1], ctx) };
                        let v2 = if is_32 { (get_operand_val(&ops[2], ctx) as u32) as u64 } else { get_operand_val(&ops[2], ctx) };
                        set_reg_val(reg, (0u64).wrapping_sub(v1.wrapping_mul(v2)), ctx);
                    }
                }
            }
            Op::SMULL => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        let v1 = get_operand_val(&ops[1], ctx) as i32 as i64;
                        let v2 = get_operand_val(&ops[2], ctx) as i32 as i64;
                        set_reg_val(reg, v1.wrapping_mul(v2) as u64, ctx);
                    }
                }
            }
            Op::UMULL => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        let v1 = get_operand_val(&ops[1], ctx) as u32 as u64;
                        let v2 = get_operand_val(&ops[2], ctx) as u32 as u64;
                        set_reg_val(reg, v1.wrapping_mul(v2), ctx);
                    }
                }
            }
            Op::SMADDL => {
                let ops = inst.operands();
                if ops.len() >= 4 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        let v1 = get_operand_val(&ops[1], ctx) as i32 as i64;
                        let v2 = get_operand_val(&ops[2], ctx) as i32 as i64;
                        let v3 = get_operand_val(&ops[3], ctx) as i64;
                        let prod = v1.wrapping_mul(v2);
                        set_reg_val(reg, v3.wrapping_add(prod) as u64, ctx);
                    }
                }
            }
            Op::UMADDL => {
                let ops = inst.operands();
                if ops.len() >= 4 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        let v1 = get_operand_val(&ops[1], ctx) as u32 as u64;
                        let v2 = get_operand_val(&ops[2], ctx) as u32 as u64;
                        let v3 = get_operand_val(&ops[3], ctx);
                        let prod = v1.wrapping_mul(v2);
                        set_reg_val(reg, v3.wrapping_add(prod), ctx);
                    }
                }
            }
            Op::SMSUBL => {
                let ops = inst.operands();
                if ops.len() >= 4 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        let v1 = get_operand_val(&ops[1], ctx) as i32 as i64;
                        let v2 = get_operand_val(&ops[2], ctx) as i32 as i64;
                        let v3 = get_operand_val(&ops[3], ctx) as i64;
                        let prod = v1.wrapping_mul(v2);
                        set_reg_val(reg, v3.wrapping_sub(prod) as u64, ctx);
                    }
                }
            }
            Op::UMSUBL => {
                let ops = inst.operands();
                if ops.len() >= 4 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        let v1 = get_operand_val(&ops[1], ctx) as u32 as u64;
                        let v2 = get_operand_val(&ops[2], ctx) as u32 as u64;
                        let v3 = get_operand_val(&ops[3], ctx);
                        let prod = v1.wrapping_mul(v2);
                        set_reg_val(reg, v3.wrapping_sub(prod), ctx);
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
            Op::ADR => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        let target_addr = get_operand_val(&ops[1], ctx);
                        set_reg_val(reg, target_addr, ctx);
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
            Op::TBZ | Op::TBNZ => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    let val = get_operand_val(&ops[0], ctx);
                    let bit = get_operand_val(&ops[1], ctx);
                    let target = get_operand_val(&ops[2], ctx);
                    let bit_set = (val & (1u64 << bit)) != 0;
                    let should_branch = if inst.op() == Op::TBNZ { bit_set } else { !bit_set };
                    if should_branch {
                        next_pc = target;
                    }
                }
            }
            Op::BL | Op::BLR => {
                let ops = inst.operands();
                if !ops.is_empty() {
                    ctx.set_x(30, pc + 4);
                    let target_addr = get_operand_val(&ops[0], ctx);
                    next_pc = target_addr;
                }
            }
            Op::BR => {
                let ops = inst.operands();
                if !ops.is_empty() {
                    let target_addr = get_operand_val(&ops[0], ctx);
                    if target_addr == 0x5671f0 {
                        let x1 = ctx.get_x(1);
                        tracing::info!("[echo_main entry] X0={:#x} X1={:#x}", ctx.get_x(0), x1);
                        for i in 0..6 {
                            if let Ok(ptr_bytes) = mem.read(x1 + i * 8, 8) {
                                let ptr = u64::from_le_bytes(ptr_bytes.try_into().unwrap());
                                let s = if ptr != 0 {
                                    mem.read_string(ptr).map(|b| String::from_utf8_lossy(&b).to_string()).unwrap_or_else(|_| "INVALID".to_string())
                                } else {
                                    "NULL".to_string()
                                };
                                tracing::info!("  argv[{}] = {:#x} ({:?})", i, ptr, s);
                            }
                        }
                    }
                    next_pc = target_addr;
                }
            }
            Op::RET => {
                let ret_addr = ctx.get_x(30);
                next_pc = ret_addr;
            }
            Op::LDR | Op::LDUR | Op::LDAXR | Op::LDXR | Op::LDAR => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        if let Some(addr) = eval_mem_addr(&ops[1], ctx) {
                            if is_w_reg(reg) {
                                let val_bytes = mem.read(addr, 4).map_err(|e| m_err(pc, e))?;
                                let val = u32::from_le_bytes(val_bytes.try_into().unwrap()) as u64;
                                set_reg_val(reg, val, ctx);
                            } else if let Some(idx) = v_reg_idx(reg) {
                                let sz = reg_size(reg);
                                let val_bytes = mem.read(addr, sz).map_err(|e| m_err(pc, e))?;
                                ctx.v[idx] = [0u8; 16];
                                ctx.v[idx][..sz].copy_from_slice(&val_bytes);
                            } else {
                                let val_bytes = mem.read(addr, 8).map_err(|e| m_err(pc, e))?;
                                let val = u64::from_le_bytes(val_bytes.try_into().unwrap());
                                set_reg_val(reg, val, ctx);
                            }
                        }
                    }
                }
            }
            Op::LDRSW | Op::LDURSW => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        if let Some(addr) = eval_mem_addr(&ops[1], ctx) {
                            let val_bytes = mem.read(addr, 4).map_err(|e| m_err(pc, e))?;
                            let val = i32::from_le_bytes(val_bytes.try_into().unwrap()) as i64 as u64;
                            set_reg_val(reg, val, ctx);
                        }
                    }
                }
            }
            Op::LDRH | Op::LDURH => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        if let Some(addr) = eval_mem_addr(&ops[1], ctx) {
                            let val_bytes = mem.read(addr, 2).map_err(|e| m_err(pc, e))?;
                            let val = u16::from_le_bytes(val_bytes.try_into().unwrap()) as u64;
                            set_reg_val(reg, val, ctx);
                        }
                    }
                }
            }
            Op::LDRSH | Op::LDURSH => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        if let Some(addr) = eval_mem_addr(&ops[1], ctx) {
                            let val_bytes = mem.read(addr, 2).map_err(|e| m_err(pc, e))?;
                            let h = i16::from_le_bytes(val_bytes.try_into().unwrap());
                            let val = if is_w_reg(reg) {
                                (h as i32) as u32 as u64
                            } else {
                                (h as i64) as u64
                            };
                            set_reg_val(reg, val, ctx);
                        }
                    }
                }
            }
            Op::STR | Op::STUR | Op::STLR => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        let val = get_operand_val(&ops[0], ctx);
                        if let Some(addr) = eval_mem_addr(&ops[1], ctx) {
                            if is_w_reg(reg) {
                                let b = (val as u32).to_le_bytes();
                                mem.write(addr, &b).map_err(|e| m_err(pc, e))?;
                            } else if let Some(idx) = v_reg_idx(reg) {
                                let sz = reg_size(reg);
                                mem.write(addr, &ctx.v[idx][..sz]).map_err(|e| m_err(pc, e))?;
                            } else {
                                mem.write(addr, &val.to_le_bytes()).map_err(|e| m_err(pc, e))?;
                            }
                        }
                    }
                }
            }
            Op::STLXR | Op::STXR => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    if let Operand::Reg { reg: status_reg, .. } = ops[0] {
                        let val = get_operand_val(&ops[1], ctx);
                        if let Some(addr) = eval_mem_addr(&ops[2], ctx) {
                            mem.write(addr, &val.to_le_bytes()).map_err(|e| m_err(pc, e))?;
                            set_reg_val(status_reg, 0, ctx);
                        }
                    }
                }
            }
            Op::STLXRB | Op::STXRB => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    if let Operand::Reg { reg: status_reg, .. } = ops[0] {
                        let val = get_operand_val(&ops[1], ctx) as u8;
                        if let Some(addr) = eval_mem_addr(&ops[2], ctx) {
                            mem.write(addr, &[val]).map_err(|e| m_err(pc, e))?;
                            set_reg_val(status_reg, 0, ctx);
                        }
                    }
                }
            }
            Op::STRH | Op::STURH => {
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
                    let r1 = get_op_reg(&ops[0]).unwrap_or(Reg::XZR);
                    let r2 = get_op_reg(&ops[1]).unwrap_or(Reg::XZR);
                    if let Some(addr) = eval_mem_addr(&ops[2], ctx) {
                        if let (Some(vidx1), Some(vidx2)) = (v_reg_idx(r1), v_reg_idx(r2)) {
                            let sz = reg_size(r1);
                            mem.write(addr, &ctx.v[vidx1][..sz]).map_err(|e| m_err(pc, e))?;
                            mem.write(addr + sz as u64, &ctx.v[vidx2][..sz]).map_err(|e| m_err(pc, e))?;
                        } else if is_w_reg(r1) {
                            let v1 = get_operand_val(&ops[0], ctx) as u32;
                            let v2 = get_operand_val(&ops[1], ctx) as u32;
                            mem.write(addr, &v1.to_le_bytes()).map_err(|e| m_err(pc, e))?;
                            mem.write(addr + 4, &v2.to_le_bytes()).map_err(|e| m_err(pc, e))?;
                        } else {
                            let v1 = get_operand_val(&ops[0], ctx);
                            let v2 = get_operand_val(&ops[1], ctx);
                            mem.write(addr, &v1.to_le_bytes()).map_err(|e| m_err(pc, e))?;
                            mem.write(addr + 8, &v2.to_le_bytes()).map_err(|e| m_err(pc, e))?;
                        }
                    }
                }
            }
            Op::LDP => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    if let (Some(r1), Some(r2)) = (get_op_reg(&ops[0]), get_op_reg(&ops[1])) {
                        if let Some(addr) = eval_mem_addr(&ops[2], ctx) {
                            if let (Some(vidx1), Some(vidx2)) = (v_reg_idx(r1), v_reg_idx(r2)) {
                                let sz = reg_size(r1);
                                let b1 = mem.read(addr, sz).map_err(|e| m_err(pc, e))?;
                                let b2 = mem.read(addr + sz as u64, sz).map_err(|e| m_err(pc, e))?;
                                ctx.v[vidx1] = [0u8; 16];
                                ctx.v[vidx1][..sz].copy_from_slice(&b1);
                                ctx.v[vidx2] = [0u8; 16];
                                ctx.v[vidx2][..sz].copy_from_slice(&b2);
                            } else if is_w_reg(r1) {
                                let b1 = mem.read(addr, 4).map_err(|e| m_err(pc, e))?;
                                let v1 = u32::from_le_bytes(b1.try_into().unwrap()) as u64;
                                let b2 = mem.read(addr + 4, 4).map_err(|e| m_err(pc, e))?;
                                let v2 = u32::from_le_bytes(b2.try_into().unwrap()) as u64;
                                set_reg_val(r1, v1, ctx);
                                set_reg_val(r2, v2, ctx);
                            } else {
                                let b1 = mem.read(addr, 8).map_err(|e| m_err(pc, e))?;
                                let v1 = u64::from_le_bytes(b1.try_into().unwrap());
                                let b2 = mem.read(addr + 8, 8).map_err(|e| m_err(pc, e))?;
                                let v2 = u64::from_le_bytes(b2.try_into().unwrap());
                                set_reg_val(r1, v1, ctx);
                                set_reg_val(r2, v2, ctx);
                            }
                        }
                    }
                }
            }
            Op::LDRB | Op::LDURB | Op::LDXRB | Op::LDAXRB | Op::LDARB => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        if let Some(addr) = eval_mem_addr(&ops[1], ctx) {
                            let b = mem.read(addr, 1).map_err(|e| m_err(pc, e))?;
                            set_reg_val(reg, b[0] as u64, ctx);
                        }
                    }
                }
            }
            Op::LDRSB | Op::LDURSB => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        if let Some(addr) = eval_mem_addr(&ops[1], ctx) {
                            let b = mem.read(addr, 1).map_err(|e| m_err(pc, e))?;
                            let val = if is_w_reg(reg) {
                                (b[0] as i8 as i32) as u32 as u64
                            } else {
                                (b[0] as i8 as i64) as u64
                            };
                            set_reg_val(reg, val, ctx);
                        }
                    }
                }
            }
            Op::STRB | Op::STURB | Op::STLRB => {
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
                    if let Some(rd) = get_op_reg(&ops[0]) {
                        if let Operand::Cond(cond) = ops[3] {
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
            }
            Op::CINC | Op::CINV | Op::CNEG => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    if let Some(rd) = get_op_reg(&ops[0]) {
                        let vn = get_operand_val(&ops[1], ctx);
                        if let Operand::Cond(cond) = ops[2] {
                            let cond_holds = eval_cond(&cond, ctx);
                            let res = if cond_holds {
                                match inst.op() {
                                    Op::CINC => vn.wrapping_add(1),
                                    Op::CINV => !vn,
                                    Op::CNEG => (-(vn as i64)) as u64,
                                    _ => vn,
                                }
                            } else {
                                vn
                            };
                            set_reg_val(rd, res, ctx);
                        }
                    }
                }
            }
            Op::CSET | Op::CSETM => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Some(rd) = get_op_reg(&ops[0]) {
                        if let Operand::Cond(cond) = ops[1] {
                            let cond_holds = eval_cond(&cond, ctx);
                            let res = if cond_holds {
                                if inst.op() == Op::CSETM { !0u64 } else { 1u64 }
                            } else {
                                0u64
                            };
                            set_reg_val(rd, res, ctx);
                        }
                    }
                }
            }
            Op::CCMP | Op::CCMN => {
                let ops = inst.operands();
                if ops.len() >= 4 {
                    if let Operand::Cond(cond) = ops[3] {
                        let cond_holds = eval_cond(&cond, ctx);
                        if cond_holds {
                            let is_32 = get_op_reg(&ops[0]).map(is_w_reg).unwrap_or(false);
                            if is_32 {
                                let v1 = get_operand_val(&ops[0], ctx) as u32;
                                let v2 = get_operand_val(&ops[1], ctx) as u32;
                                let (res, overflow) = if inst.op() == Op::CCMN {
                                    v1.overflowing_add(v2)
                                } else {
                                    v1.overflowing_sub(v2)
                                };
                                let n = (res as i32) < 0;
                                let z = res == 0;
                                let c = if inst.op() == Op::CCMN { overflow } else { !overflow };
                                let v = if inst.op() == Op::CCMN {
                                    ((v1 ^ !v2) & (v1 ^ res) & 0x8000_0000) != 0
                                } else {
                                    ((v1 ^ v2) & (v1 ^ res) & 0x8000_0000) != 0
                                };
                                ctx.set_nzcv(n, z, c, v);
                            } else {
                                let v1 = get_operand_val(&ops[0], ctx);
                                let v2 = get_operand_val(&ops[1], ctx);
                                let (res, overflow) = if inst.op() == Op::CCMN {
                                    v1.overflowing_add(v2)
                                } else {
                                    v1.overflowing_sub(v2)
                                };
                                let n = (res as i64) < 0;
                                let z = res == 0;
                                let c = if inst.op() == Op::CCMN { overflow } else { !overflow };
                                let v = if inst.op() == Op::CCMN {
                                    ((v1 ^ !v2) & (v1 ^ res) & 0x8000_0000_0000_0000) != 0
                                } else {
                                    ((v1 ^ v2) & (v1 ^ res) & 0x8000_0000_0000_0000) != 0
                                };
                                ctx.set_nzcv(n, z, c, v);
                            }
                        } else {
                            let nzcv_imm = get_operand_val(&ops[2], ctx) as u8;
                            let n = (nzcv_imm & 8) != 0;
                            let z = (nzcv_imm & 4) != 0;
                            let c = (nzcv_imm & 2) != 0;
                            let v = (nzcv_imm & 1) != 0;
                            ctx.set_nzcv(n, z, c, v);
                        }
                    }
                }
            }
            Op::MRS => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    let sysreg_str = format!("{:?}", ops[1]);
                    let val = if sysreg_str.contains("TPIDR_EL0") || sysreg_str.contains("tpidr_el0") {
                        ctx.tpidr_el0
                    } else if sysreg_str.contains("DCZID") || sysreg_str.contains("dczid") {
                        0x10u64 // DZP=1 (DC ZVA prohibited, force standard SIMD loop)
                    } else if sysreg_str.contains("CNT") {
                        1000000000u64
                    } else {
                        0
                    };
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        set_reg_val(reg, val, ctx);
                    }
                }
            }
            Op::MSR => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    let sysreg_str = format!("{:?}", ops[0]);
                    let val = get_operand_val(&ops[1], ctx);
                    if sysreg_str.contains("TPIDR_EL0") || sysreg_str.contains("tpidr_el0") {
                        ctx.tpidr_el0 = val;
                    }
                }
            }
            Op::ORR | Op::ORN => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        if let Some(idx0) = v_reg_idx(reg) {
                            let vec1 = ops.get(1).and_then(get_op_reg).and_then(v_reg_idx).map(|i| ctx.v[i]).unwrap_or([0u8; 16]);
                            let vec2 = if ops.len() >= 3 { ops.get(2).and_then(get_op_reg).and_then(v_reg_idx).map(|i| ctx.v[i]).unwrap_or([0u8; 16]) } else { [0u8; 16] };
                            let mut res = [0u8; 16];
                            let is_orn = inst.op() == Op::ORN;
                            for i in 0..16 { res[i] = if is_orn { vec1[i] | !vec2[i] } else { vec1[i] | vec2[i] }; }
                            ctx.v[idx0] = res;
                        } else {
                            let (v1, v2) = if ops.len() >= 3 {
                                (get_operand_val(&ops[1], ctx), get_operand_val(&ops[2], ctx))
                            } else {
                                (get_operand_val(&ops[0], ctx), get_operand_val(&ops[1], ctx))
                            };
                            let res = if inst.op() == Op::ORN { v1 | !v2 } else { v1 | v2 };
                            set_reg_val(reg, res, ctx);
                        }
                    }
                }
            }
            Op::EOR | Op::EON => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        if let Some(idx0) = v_reg_idx(reg) {
                            let vec1 = ops.get(1).and_then(get_op_reg).and_then(v_reg_idx).map(|i| ctx.v[i]).unwrap_or([0u8; 16]);
                            let vec2 = if ops.len() >= 3 { ops.get(2).and_then(get_op_reg).and_then(v_reg_idx).map(|i| ctx.v[i]).unwrap_or([0u8; 16]) } else { [0u8; 16] };
                            let mut res = [0u8; 16];
                            let is_eon = inst.op() == Op::EON;
                            for i in 0..16 { res[i] = if is_eon { vec1[i] ^ !vec2[i] } else { vec1[i] ^ vec2[i] }; }
                            ctx.v[idx0] = res;
                        } else {
                            let (v1, v2) = if ops.len() >= 3 {
                                (get_operand_val(&ops[1], ctx), get_operand_val(&ops[2], ctx))
                            } else {
                                (get_operand_val(&ops[0], ctx), get_operand_val(&ops[1], ctx))
                            };
                            let res = if inst.op() == Op::EON { v1 ^ !v2 } else { v1 ^ v2 };
                            set_reg_val(reg, res, ctx);
                        }
                    }
                }
            }
            Op::AND | Op::ANDS | Op::TST => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        if let Some(idx0) = v_reg_idx(reg) {
                            let vec1 = ops.get(1).and_then(get_op_reg).and_then(v_reg_idx).map(|i| ctx.v[i]).unwrap_or([0u8; 16]);
                            let vec2 = if ops.len() >= 3 {
                                ops.get(2).and_then(get_op_reg).and_then(v_reg_idx).map(|i| ctx.v[i]).unwrap_or([0u8; 16])
                            } else { [0u8; 16] };
                            let mut res = [0u8; 16];
                            for i in 0..16 { res[i] = vec1[i] & vec2[i]; }
                            ctx.v[idx0] = res;
                        } else {
                            let (op1, op2) = if inst.op() == Op::TST {
                                (&ops[0], &ops[1])
                            } else if ops.len() >= 3 {
                                (&ops[1], &ops[2])
                            } else {
                                (&ops[0], &ops[1])
                            };
                            let v1 = get_operand_val(op1, ctx);
                            let v2 = get_operand_val(op2, ctx);
                            let res = v1 & v2;
                            if inst.op() != Op::TST {
                                set_reg_val(reg, res, ctx);
                            }
                            if inst.op() == Op::ANDS || inst.op() == Op::TST {
                                let is_32 = get_op_reg(op1).map(is_w_reg).unwrap_or(false);
                                if is_32 {
                                    let r32 = res as u32;
                                    let n = (r32 as i32) < 0;
                                    let z = r32 == 0;
                                    ctx.set_nzcv(n, z, false, false);
                                } else {
                                    let n = (res as i64) < 0;
                                    let z = res == 0;
                                    ctx.set_nzcv(n, z, false, false);
                                }
                            }
                        }
                    }
                }
            }
            Op::DUP => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    let val = get_operand_val(&ops[1], ctx);
                    if let Some(rd) = get_op_reg(&ops[0]) {
                        if let Some(idx) = v_reg_idx(rd) {
                            let elem_sz = get_vec_elem_size(&ops[0]);
                            ctx.v[idx] = [0u8; 16];
                            match elem_sz {
                                1 => ctx.v[idx].fill((val & 0xff) as u8),
                                2 => {
                                    let bytes = ((val & 0xffff) as u16).to_le_bytes();
                                    for i in 0..8 {
                                        ctx.v[idx][i * 2..i * 2 + 2].copy_from_slice(&bytes);
                                    }
                                }
                                4 => {
                                    let bytes = ((val & 0xffffffff) as u32).to_le_bytes();
                                    for i in 0..4 {
                                        ctx.v[idx][i * 4..i * 4 + 4].copy_from_slice(&bytes);
                                    }
                                }
                                _ => {
                                    let bytes = val.to_le_bytes();
                                    for i in 0..2 {
                                        ctx.v[idx][i * 8..i * 8 + 8].copy_from_slice(&bytes);
                                    }
                                }
                            }
                        } else {
                            set_reg_val(rd, val, ctx);
                        }
                    }
                }
            }
            Op::USHL | Op::SHL | Op::SSHL => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Some(rd) = get_op_reg(&ops[0]) {
                        if let Some(idx0) = v_reg_idx(rd) {
                            let elem_sz = get_vec_elem_size(&ops[0]);
                            let vn = ops.get(1).and_then(get_op_reg).and_then(v_reg_idx).map(|i| ctx.v[i]).unwrap_or([0u8; 16]);
                            let shift_vec = if ops.len() >= 3 {
                                ops.get(2).and_then(get_op_reg).and_then(v_reg_idx).map(|i| ctx.v[i])
                            } else { None };

                            let imm_shift = if shift_vec.is_none() && ops.len() >= 3 {
                                get_operand_val(&ops[2], ctx) as i32
                            } else { 0 };

                            let mut res = [0u8; 16];
                            let num_elems = 16 / elem_sz;
                            for i in 0..num_elems {
                                let shift = if let Some(svec) = shift_vec {
                                    match elem_sz {
                                        1 => svec[i] as i8 as i32,
                                        2 => u16::from_le_bytes(svec[i*2..i*2+2].try_into().unwrap()) as i16 as i32,
                                        4 => u32::from_le_bytes(svec[i*4..i*4+4].try_into().unwrap()) as i32,
                                        _ => u64::from_le_bytes(svec[i*8..i*8+8].try_into().unwrap()) as i64 as i32,
                                    }
                                } else {
                                    imm_shift
                                };

                                match elem_sz {
                                    1 => {
                                        let val = vn[i];
                                        res[i] = if shift >= 0 { val.wrapping_shl(shift as u32) } else { val.wrapping_shr((-shift) as u32) };
                                    }
                                    2 => {
                                        let val = u16::from_le_bytes(vn[i*2..i*2+2].try_into().unwrap());
                                        let s_res = if shift >= 0 { val.wrapping_shl(shift as u32) } else { val.wrapping_shr((-shift) as u32) };
                                        res[i*2..i*2+2].copy_from_slice(&s_res.to_le_bytes());
                                    }
                                    4 => {
                                        let val = u32::from_le_bytes(vn[i*4..i*4+4].try_into().unwrap());
                                        let s_res = if shift >= 0 { val.wrapping_shl(shift as u32) } else { val.wrapping_shr((-shift) as u32) };
                                        res[i*4..i*4+4].copy_from_slice(&s_res.to_le_bytes());
                                    }
                                    _ => {
                                        let val = u64::from_le_bytes(vn[i*8..i*8+8].try_into().unwrap());
                                        let s_res = if shift >= 0 { val.wrapping_shl(shift as u32) } else { val.wrapping_shr((-shift) as u32) };
                                        res[i*8..i*8+8].copy_from_slice(&s_res.to_le_bytes());
                                    }
                                }
                            }
                            ctx.v[idx0] = res;
                        }
                    }
                }
            }
            Op::CMEQ | Op::CMHI | Op::CMHS | Op::CMGT | Op::CMGE | Op::CMTST => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Some(rd) = get_op_reg(&ops[0]) {
                        if let Some(idx0) = v_reg_idx(rd) {
                            let elem_sz = get_vec_elem_size(&ops[0]);
                            let vec1 = ops.get(1).and_then(get_op_reg).and_then(v_reg_idx).map(|i| ctx.v[i]).unwrap_or([0u8; 16]);
                            let vec2 = if ops.len() >= 3 {
                                ops.get(2).and_then(get_op_reg).and_then(v_reg_idx).map(|i| ctx.v[i])
                            } else { None };
                            let imm_val = if vec2.is_none() && ops.len() >= 3 {
                                get_operand_val(&ops[2], ctx)
                            } else { 0 };

                            let mut res = [0u8; 16];
                            let num_elems = 16 / elem_sz;
                            for i in 0..num_elems {
                                let (v1, v2) = match elem_sz {
                                    1 => (vec1[i] as u64, vec2.map(|v| v[i] as u64).unwrap_or(imm_val)),
                                    2 => (u16::from_le_bytes(vec1[i*2..i*2+2].try_into().unwrap()) as u64, vec2.map(|v| u16::from_le_bytes(v[i*2..i*2+2].try_into().unwrap()) as u64).unwrap_or(imm_val)),
                                    4 => (u32::from_le_bytes(vec1[i*4..i*4+4].try_into().unwrap()) as u64, vec2.map(|v| u32::from_le_bytes(v[i*4..i*4+4].try_into().unwrap()) as u64).unwrap_or(imm_val)),
                                    _ => (u64::from_le_bytes(vec1[i*8..i*8+8].try_into().unwrap()), vec2.map(|v| u64::from_le_bytes(v[i*8..i*8+8].try_into().unwrap())).unwrap_or(imm_val)),
                                };

                                let cond = match inst.op() {
                                    Op::CMEQ => v1 == v2,
                                    Op::CMHI => v1 > v2,
                                    Op::CMHS => v1 >= v2,
                                    Op::CMGT => match elem_sz {
                                        1 => (v1 as i8) > (v2 as i8),
                                        2 => (v1 as i16) > (v2 as i16),
                                        4 => (v1 as i32) > (v2 as i32),
                                        _ => (v1 as i64) > (v2 as i64),
                                    },
                                    Op::CMGE => match elem_sz {
                                        1 => (v1 as i8) >= (v2 as i8),
                                        2 => (v1 as i16) >= (v2 as i16),
                                        4 => (v1 as i32) >= (v2 as i32),
                                        _ => (v1 as i64) >= (v2 as i64),
                                    },
                                    Op::CMTST => (v1 & v2) != 0,
                                    _ => false,
                                };

                                let mask = if cond { 0xffu8 } else { 0x00u8 };
                                for k in 0..elem_sz {
                                    res[i * elem_sz + k] = mask;
                                }
                            }
                            ctx.v[idx0] = res;
                        }
                    }
                }
            }
            Op::REV => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        let val = get_operand_val(&ops[1], ctx);
                        if is_w_reg(reg) {
                            let swapped = (val as u32).swap_bytes() as u64;
                            set_reg_val(reg, swapped, ctx);
                        } else {
                            set_reg_val(reg, val.swap_bytes(), ctx);
                        }
                    }
                }
            }
            Op::CLZ => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        let val = get_operand_val(&ops[1], ctx);
                        let count = if is_w_reg(reg) {
                            (val as u32).leading_zeros() as u64
                        } else {
                            val.leading_zeros() as u64
                        };
                        set_reg_val(reg, count, ctx);
                    }
                }
            }
            Op::LD1 | Op::LD1R => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    let regs = get_multi_regs(&ops[0]);
                    if let Some(mut addr) = eval_mem_addr(&ops[1], ctx) {
                        for reg in regs {
                            if inst.op() == Op::LD1R {
                                let elem_sz = get_vec_elem_size(&ops[0]);
                                let val_bytes = mem.read(addr, elem_sz).map_err(|e| m_err(pc, e))?;
                                if let Some(idx) = v_reg_idx(reg) {
                                    for chunk in ctx.v[idx].chunks_exact_mut(elem_sz) {
                                        chunk.copy_from_slice(&val_bytes);
                                    }
                                }
                            } else {
                                let sz = if is_64bit_vector(&ops[0]) { 8 } else { 16 };
                                let val_bytes = mem.read(addr, sz).map_err(|e| m_err(pc, e))?;
                                if let Some(idx) = v_reg_idx(reg) {
                                    ctx.v[idx] = [0u8; 16];
                                    ctx.v[idx][..sz].copy_from_slice(&val_bytes);
                                }
                                addr += sz as u64;
                            }
                        }
                        if ops.len() >= 3 {
                            let post_off = match &ops[2] {
                                Operand::Imm32 { imm, .. } => imm_to_i64(imm),
                                Operand::Imm64 { imm, .. } => imm_to_i64(imm),
                                op => get_op_reg(op).map(|r| get_reg_val(r, ctx) as i64).unwrap_or(0),
                            };
                            if post_off != 0 {
                                if let Operand::MemOffset { reg: base_reg, .. } = ops[1] {
                                    let cur = get_reg_val(base_reg, ctx);
                                    set_reg_val(base_reg, (cur as i64 + post_off) as u64, ctx);
                                }
                            }
                        }
                    }
                }
            }
            Op::ST1 => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    let regs = get_multi_regs(&ops[0]);
                    if let Some(mut addr) = eval_mem_addr(&ops[1], ctx) {
                        for reg in regs {
                            let sz = if is_64bit_vector(&ops[0]) { 8 } else { 16 };
                            if let Some(idx) = v_reg_idx(reg) {
                                mem.write(addr, &ctx.v[idx][..sz]).map_err(|e| m_err(pc, e))?;
                            }
                            addr += sz as u64;
                        }
                        if ops.len() >= 3 {
                            let post_off = match &ops[2] {
                                Operand::Imm32 { imm, .. } => imm_to_i64(imm),
                                Operand::Imm64 { imm, .. } => imm_to_i64(imm),
                                op => get_op_reg(op).map(|r| get_reg_val(r, ctx) as i64).unwrap_or(0),
                            };
                            if post_off != 0 {
                                if let Operand::MemOffset { reg: base_reg, .. } = ops[1] {
                                    let cur = get_reg_val(base_reg, ctx);
                                    set_reg_val(base_reg, (cur as i64 + post_off) as u64, ctx);
                                }
                            }
                        }
                    }
                }
            }
            Op::LD2 | Op::LD3 | Op::LD4 => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    let regs = get_multi_regs(&ops[0]);
                    let n_regs = regs.len();
                    if let Some(addr) = eval_mem_addr(&ops[1], ctx) {
                        let total_bytes = n_regs * 16;
                        if let Ok(bytes) = mem.read(addr, total_bytes) {
                            for r_idx in 0..n_regs {
                                if let Some(v_idx) = v_reg_idx(regs[r_idx]) {
                                    for elem in 0..4 {
                                        let src_off = (elem * n_regs + r_idx) * 4;
                                        if src_off + 4 <= bytes.len() {
                                            ctx.v[v_idx][elem * 4..(elem + 1) * 4].copy_from_slice(&bytes[src_off..src_off + 4]);
                                        }
                                    }
                                }
                            }
                        }
                        if ops.len() >= 3 {
                            let post_off = match &ops[2] {
                                Operand::Imm32 { imm, .. } => imm_to_i64(imm),
                                Operand::Imm64 { imm, .. } => imm_to_i64(imm),
                                op => get_op_reg(op).map(|r| get_reg_val(r, ctx) as i64).unwrap_or(total_bytes as i64),
                            };
                            if let Operand::MemOffset { reg: base_reg, .. } = ops[1] {
                                let cur = get_reg_val(base_reg, ctx);
                                set_reg_val(base_reg, (cur as i64 + post_off) as u64, ctx);
                            }
                        }
                    }
                }
            }
            Op::SBFIZ | Op::UBFIZ => {
                let ops = inst.operands();
                if ops.len() >= 4 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        let val = get_operand_val(&ops[1], ctx);
                        let arg2 = get_operand_val(&ops[2], ctx);
                        let arg3 = get_operand_val(&ops[3], ctx);
                        let is_32 = is_w_reg(reg);
                        let n_bits = if is_32 { 32u64 } else { 64u64 };

                        let (lsb, width) = if arg2 + arg3 < n_bits {
                            (arg2, arg3)
                        } else {
                            let immr = arg2 % n_bits;
                            let imms = arg3 % n_bits;
                            let lsb = (n_bits - immr) % n_bits;
                            let width = imms + 1;
                            (lsb, width)
                        };

                        let mask = if width >= 64 { !0u64 } else { (1u64 << width) - 1 };
                        let truncated = val & mask;
                        let res = if inst.op() == Op::SBFIZ && width > 0 && (truncated & (1u64 << (width - 1))) != 0 {
                            let sign_ext = !0u64 << width;
                            (truncated | sign_ext) << lsb
                        } else {
                            truncated << lsb
                        };
                        set_reg_val(reg, res, ctx);
                    }
                }
            }
            Op::ADDP => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    let vec1 = ops.get(1).and_then(get_op_reg).and_then(v_reg_idx).map(|idx| ctx.v[idx]).unwrap_or([0u8; 16]);
                    let vec2 = if ops.len() >= 3 {
                        ops.get(2).and_then(get_op_reg).and_then(v_reg_idx).map(|idx| ctx.v[idx]).unwrap_or(vec1)
                    } else { vec1 };
                    let elem_sz = get_vec_elem_size(&ops[0]);
                    let is_64 = is_64bit_vector(&ops[0]);
                    let mut res = [0u8; 16];
                    match elem_sz {
                        1 => {
                            let count = if is_64 { 4 } else { 8 };
                            for i in 0..count {
                                res[i] = vec1[i * 2].wrapping_add(vec1[i * 2 + 1]);
                            }
                            if !is_64 {
                                for i in 0..4 {
                                    res[4 + i] = vec2[i * 2].wrapping_add(vec2[i * 2 + 1]);
                                }
                            }
                        }
                        2 => {
                            let count = if is_64 { 2 } else { 4 };
                            for i in 0..count {
                                let a = u16::from_le_bytes([vec1[i * 4], vec1[i * 4 + 1]]);
                                let b = u16::from_le_bytes([vec1[i * 4 + 2], vec1[i * 4 + 3]]);
                                res[i * 2..i * 2 + 2].copy_from_slice(&a.wrapping_add(b).to_le_bytes());
                            }
                            if !is_64 {
                                for i in 0..2 {
                                    let a = u16::from_le_bytes([vec2[i * 4], vec2[i * 4 + 1]]);
                                    let b = u16::from_le_bytes([vec2[i * 4 + 2], vec2[i * 4 + 3]]);
                                    res[4 + i * 2..4 + i * 2 + 2].copy_from_slice(&a.wrapping_add(b).to_le_bytes());
                                }
                            }
                        }
                        4 => {
                            let count = if is_64 { 1 } else { 2 };
                            for i in 0..count {
                                let a = u32::from_le_bytes(vec1[i * 8..i * 8 + 4].try_into().unwrap());
                                let b = u32::from_le_bytes(vec1[i * 8 + 4..i * 8 + 8].try_into().unwrap());
                                res[i * 4..i * 4 + 4].copy_from_slice(&a.wrapping_add(b).to_le_bytes());
                            }
                            if !is_64 {
                                let a = u32::from_le_bytes(vec2[0..4].try_into().unwrap());
                                let b = u32::from_le_bytes(vec2[4..8].try_into().unwrap());
                                res[8..12].copy_from_slice(&a.wrapping_add(b).to_le_bytes());
                            }
                        }
                        _ => {
                            let a = u64::from_le_bytes(vec1[..8].try_into().unwrap());
                            let b = u64::from_le_bytes(vec1[8..16].try_into().unwrap());
                            res[..8].copy_from_slice(&a.wrapping_add(b).to_le_bytes());
                            if !is_64 {
                                let c = u64::from_le_bytes(vec2[..8].try_into().unwrap());
                                let d = u64::from_le_bytes(vec2[8..16].try_into().unwrap());
                                res[8..16].copy_from_slice(&c.wrapping_add(d).to_le_bytes());
                            }
                        }
                    }
                    if let Some(reg) = ops.get(0).and_then(get_op_reg) {
                        if let Some(idx) = v_reg_idx(reg) {
                            ctx.v[idx] = res;
                        } else {
                            let val = u64::from_le_bytes(res[..8].try_into().unwrap());
                            set_reg_val(reg, val, ctx);
                        }
                    }
                }
            }
            Op::EXT => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    let vec1 = ops.get(1).and_then(get_op_reg).and_then(v_reg_idx).map(|idx| ctx.v[idx]).unwrap_or([0u8; 16]);
                    let vec2 = ops.get(2).and_then(get_op_reg).and_then(v_reg_idx).map(|idx| ctx.v[idx]).unwrap_or([0u8; 16]);
                    let shift_op = if ops.len() >= 4 { &ops[3] } else { &ops[2] };
                    let shift = (get_operand_val(shift_op, ctx) as usize) & 0xf;
                    let mut concat = [0u8; 32];
                    concat[..16].copy_from_slice(&vec1);
                    concat[16..32].copy_from_slice(&vec2);
                    let mut res = [0u8; 16];
                    res.copy_from_slice(&concat[shift..shift + 16]);
                    if let Some(reg) = ops.get(0).and_then(get_op_reg) {
                        if let Some(idx) = v_reg_idx(reg) {
                            ctx.v[idx] = res;
                        } else {
                            let val = u64::from_le_bytes(res[..8].try_into().unwrap());
                            set_reg_val(reg, val, ctx);
                        }
                    }
                }
            }
            Op::BIT | Op::BIF | Op::BSL => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    let d = ops.get(0).and_then(get_op_reg).and_then(v_reg_idx).map(|idx| ctx.v[idx]).unwrap_or([0u8; 16]);
                    let n = ops.get(1).and_then(get_op_reg).and_then(v_reg_idx).map(|idx| ctx.v[idx]).unwrap_or([0u8; 16]);
                    let m = ops.get(2).and_then(get_op_reg).and_then(v_reg_idx).map(|idx| ctx.v[idx]).unwrap_or([0u8; 16]);
                    let mut res = [0u8; 16];
                    for i in 0..16 {
                        res[i] = match inst.op() {
                            Op::BIT => (d[i] & !m[i]) | (n[i] & m[i]),
                            Op::BIF => (d[i] & m[i]) | (n[i] & !m[i]),
                            Op::BSL => (n[i] & d[i]) | (m[i] & !d[i]),
                            _ => 0,
                        };
                    }
                    if let Some(reg) = ops.get(0).and_then(get_op_reg) {
                        if let Some(idx) = v_reg_idx(reg) {
                            ctx.v[idx] = res;
                        } else {
                            let val = u64::from_le_bytes(res[..8].try_into().unwrap());
                            set_reg_val(reg, val, ctx);
                        }
                    }
                }
            }

            Op::MVNI => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        if let Some(idx0) = v_reg_idx(reg) {
                            let elem_sz = get_vec_elem_size(&ops[0]);
                            let imm = get_operand_val(&ops[1], ctx);
                            let not_imm = !imm;
                            let mut res = [0u8; 16];
                            let num_elems = 16 / elem_sz;
                            for i in 0..num_elems {
                                match elem_sz {
                                    1 => res[i] = (not_imm & 0xff) as u8,
                                    2 => res[i*2..i*2+2].copy_from_slice(&((not_imm & 0xffff) as u16).to_le_bytes()),
                                    4 => res[i*4..i*4+4].copy_from_slice(&((not_imm & 0xffffffff) as u32).to_le_bytes()),
                                    _ => res[i*8..i*8+8].copy_from_slice(&not_imm.to_le_bytes()),
                                }
                            }
                            ctx.v[idx0] = res;
                        } else {
                            let imm = get_operand_val(&ops[1], ctx);
                            set_reg_val(reg, !imm, ctx);
                        }
                    }
                }
            }
            Op::RBIT => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        if let Some(idx0) = v_reg_idx(reg) {
                            let vec1 = ops.get(1).and_then(get_op_reg).and_then(v_reg_idx).map(|idx1| ctx.v[idx1]).unwrap_or([0u8; 16]);
                            let mut res = [0u8; 16];
                            for i in 0..16 { res[i] = vec1[i].reverse_bits(); }
                            ctx.v[idx0] = res;
                        } else {
                            let val = get_operand_val(&ops[1], ctx);
                            if is_w_reg(reg) {
                                let reversed = (val as u32).reverse_bits() as u64;
                                set_reg_val(reg, reversed, ctx);
                            } else {
                                set_reg_val(reg, val.reverse_bits(), ctx);
                            }
                        }
                    }
                }
            }
            Op::REV16 | Op::REV32 | Op::REV64 => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        if let Some(idx0) = v_reg_idx(reg) {
                            let vec1 = if let Operand::Reg { reg: r1, .. } = ops[1] {
                                if let Some(idx1) = v_reg_idx(r1) { ctx.v[idx1] } else { [0u8; 16] }
                            } else { [0u8; 16] };
                            let mut res = [0u8; 16];
                            let sz = match inst.op() {
                                Op::REV16 => 2,
                                Op::REV32 => 4,
                                _ => 8,
                            };
                            for chunk in 0..(16 / sz) {
                                for byte in 0..sz {
                                    res[chunk * sz + byte] = vec1[chunk * sz + (sz - 1 - byte)];
                                }
                            }
                            ctx.v[idx0] = res;
                        } else {
                            let val = get_operand_val(&ops[1], ctx);
                            let res = match inst.op() {
                                Op::REV16 => {
                                    let b0 = (val & 0xff00ff00ff00ff00) >> 8;
                                    let b1 = (val & 0x00ff00ff00ff00ff) << 8;
                                    b0 | b1
                                }
                                Op::REV32 => {
                                    let hi = ((val >> 32) as u32).swap_bytes() as u64;
                                    let lo = (val as u32).swap_bytes() as u64;
                                    (hi << 32) | lo
                                }
                                _ => val.swap_bytes(),
                            };
                            set_reg_val(reg, res, ctx);
                        }
                    }
                }
            }
            Op::SHRN | Op::SHRN2 => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    let vec1 = ops.get(1).and_then(get_op_reg).and_then(v_reg_idx).map(|idx| ctx.v[idx]).unwrap_or([0u8; 16]);
                    let shift = (get_operand_val(&ops[2], ctx) as u32) & 0x3f;
                    let is_high = inst.op() == Op::SHRN2;
                    let mut res = if is_high {
                        ops.get(0).and_then(get_op_reg).and_then(v_reg_idx).map(|idx| ctx.v[idx]).unwrap_or([0u8; 16])
                    } else {
                        [0u8; 16]
                    };
                    let elem_sz = get_vec_elem_size(&ops[1]);
                    match elem_sz {
                        4 => {
                            let start = if is_high { 8 } else { 0 };
                            for i in 0..4 {
                                let w = u32::from_le_bytes(vec1[i * 4..i * 4 + 4].try_into().unwrap());
                                let val = ((w >> shift) & 0xffff) as u16;
                                res[start + i * 2..start + i * 2 + 2].copy_from_slice(&val.to_le_bytes());
                            }
                        }
                        8 => {
                            let start = if is_high { 8 } else { 0 };
                            for i in 0..2 {
                                let d = u64::from_le_bytes(vec1[i * 8..i * 8 + 8].try_into().unwrap());
                                let val = ((d >> shift) & 0xffffffff) as u32;
                                res[start + i * 4..start + i * 4 + 4].copy_from_slice(&val.to_le_bytes());
                            }
                        }
                        _ => {
                            let start = if is_high { 8 } else { 0 };
                            for i in 0..8 {
                                let h = u16::from_le_bytes([vec1[i * 2], vec1[i * 2 + 1]]);
                                res[start + i] = ((h >> shift) & 0xff) as u8;
                            }
                        }
                    }
                    if let Some(reg) = ops.get(0).and_then(get_op_reg) {
                        if let Some(idx) = v_reg_idx(reg) {
                            ctx.v[idx] = res;
                        } else {
                            let val = u64::from_le_bytes(res[..8].try_into().unwrap());
                            set_reg_val(reg, val, ctx);
                        }
                    }
                }
            }
            Op::UMINP | Op::UMAXP | Op::SMINP | Op::SMAXP => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    let vec1 = ops.get(1).and_then(get_op_reg).and_then(v_reg_idx).map(|idx| ctx.v[idx]).unwrap_or([0u8; 16]);
                    let vec2 = if ops.len() >= 3 {
                        ops.get(2).and_then(get_op_reg).and_then(v_reg_idx).map(|idx| ctx.v[idx]).unwrap_or(vec1)
                    } else { vec1 };
                    let elem_sz = get_vec_elem_size(&ops[0]);
                    let is_64 = is_64bit_vector(&ops[0]);
                    let mut res = [0u8; 16];
                    match elem_sz {
                        1 => {
                            let calc_u8 = |a: u8, b: u8| match inst.op() {
                                Op::UMAXP => a.max(b),
                                Op::UMINP => a.min(b),
                                Op::SMAXP => (a as i8).max(b as i8) as u8,
                                Op::SMINP => (a as i8).min(b as i8) as u8,
                                _ => 0,
                            };
                            let count = if is_64 { 4 } else { 8 };
                            for i in 0..count {
                                res[i] = calc_u8(vec1[i * 2], vec1[i * 2 + 1]);
                            }
                            if !is_64 {
                                for i in 0..8 {
                                    res[8 + i] = calc_u8(vec2[i * 2], vec2[i * 2 + 1]);
                                }
                            }
                        }
                        2 => {
                            let calc_u16 = |a: u16, b: u16| match inst.op() {
                                Op::UMAXP => a.max(b),
                                Op::UMINP => a.min(b),
                                Op::SMAXP => (a as i16).max(b as i16) as u16,
                                Op::SMINP => (a as i16).min(b as i16) as u16,
                                _ => 0,
                            };
                            let count = if is_64 { 2 } else { 4 };
                            for i in 0..count {
                                let a = u16::from_le_bytes([vec1[i * 4], vec1[i * 4 + 1]]);
                                let b = u16::from_le_bytes([vec1[i * 4 + 2], vec1[i * 4 + 3]]);
                                res[i * 2..i * 2 + 2].copy_from_slice(&calc_u16(a, b).to_le_bytes());
                            }
                            if !is_64 {
                                for i in 0..4 {
                                    let a = u16::from_le_bytes([vec2[i * 4], vec2[i * 4 + 1]]);
                                    let b = u16::from_le_bytes([vec2[i * 4 + 2], vec2[i * 4 + 3]]);
                                    res[8 + i * 2..8 + i * 2 + 2].copy_from_slice(&calc_u16(a, b).to_le_bytes());
                                }
                            }
                        }
                        4 => {
                            let calc_u32 = |a: u32, b: u32| match inst.op() {
                                Op::UMAXP => a.max(b),
                                Op::UMINP => a.min(b),
                                Op::SMAXP => (a as i32).max(b as i32) as u32,
                                Op::SMINP => (a as i32).min(b as i32) as u32,
                                _ => 0,
                            };
                            let count = if is_64 { 1 } else { 2 };
                            for i in 0..count {
                                let a = u32::from_le_bytes(vec1[i * 8..i * 8 + 4].try_into().unwrap());
                                let b = u32::from_le_bytes(vec1[i * 8 + 4..i * 8 + 8].try_into().unwrap());
                                res[i * 4..i * 4 + 4].copy_from_slice(&calc_u32(a, b).to_le_bytes());
                            }
                            if !is_64 {
                                for i in 0..2 {
                                    let a = u32::from_le_bytes(vec2[i * 8..i * 8 + 4].try_into().unwrap());
                                    let b = u32::from_le_bytes(vec2[i * 8 + 4..i * 8 + 8].try_into().unwrap());
                                    res[8 + i * 4..8 + i * 4 + 4].copy_from_slice(&calc_u32(a, b).to_le_bytes());
                                }
                            }
                        }
                        _ => {}
                    }
                    if let Some(reg) = ops.get(0).and_then(get_op_reg) {
                        if let Some(idx) = v_reg_idx(reg) {
                            ctx.v[idx] = res;
                        } else {
                            let val = u64::from_le_bytes(res[..8].try_into().unwrap());
                            set_reg_val(reg, val, ctx);
                        }
                    }
                }
            }
            Op::CNT => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    let r1 = get_op_reg(&ops[0]);
                    let r2 = get_op_reg(&ops[1]);
                    if let (Some(r1), Some(r2)) = (r1, r2) {
                        let idx1 = v_reg_idx(r1).unwrap_or(0);
                        let idx2 = v_reg_idx(r2).unwrap_or(0);
                        let mut res = [0u8; 16];
                        for i in 0..16 {
                            res[i] = ctx.v[idx2][i].count_ones() as u8;
                        }
                        ctx.v[idx1] = res;
                    }
                }
            }
            Op::ADDV | Op::UADDLV | Op::SADDLV | Op::UMAXV | Op::UMINV | Op::SMAXV | Op::SMINV => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    let r1 = get_op_reg(&ops[0]);
                    let r2 = get_op_reg(&ops[1]);
                    if let (Some(r1), Some(r2)) = (r1, r2) {
                        let idx1 = v_reg_idx(r1).unwrap_or(0);
                        let idx2 = v_reg_idx(r2).unwrap_or(0);
                        let elem_sz = get_vec_elem_size(&ops[1]);
                        let is_64 = is_64bit_vector(&ops[1]);
                        let mut res = [0u8; 16];
                        match elem_sz {
                            1 => {
                                let count = if is_64 { 8 } else { 16 };
                                match inst.op() {
                                    Op::ADDV | Op::UADDLV => {
                                        let sum: u64 = ctx.v[idx2][..count].iter().map(|&b| b as u64).sum();
                                        res[..8].copy_from_slice(&sum.to_le_bytes());
                                    }
                                    Op::SADDLV => {
                                        let sum: i64 = ctx.v[idx2][..count].iter().map(|&b| b as i8 as i64).sum();
                                        res[..8].copy_from_slice(&(sum as u64).to_le_bytes());
                                    }
                                    Op::UMAXV => {
                                        res[0] = ctx.v[idx2][..count].iter().copied().max().unwrap_or(0);
                                    }
                                    Op::UMINV => {
                                        res[0] = ctx.v[idx2][..count].iter().copied().min().unwrap_or(0);
                                    }
                                    Op::SMAXV => {
                                        res[0] = ctx.v[idx2][..count].iter().map(|&b| b as i8).max().unwrap_or(0) as u8;
                                    }
                                    Op::SMINV => {
                                        res[0] = ctx.v[idx2][..count].iter().map(|&b| b as i8).min().unwrap_or(0) as u8;
                                    }
                                    _ => {}
                                }
                            }
                            2 => {
                                let count = if is_64 { 4 } else { 8 };
                                let slice = &ctx.v[idx2];
                                let elems: Vec<u16> = (0..count).map(|i| u16::from_le_bytes([slice[i*2], slice[i*2+1]])).collect();
                                match inst.op() {
                                    Op::ADDV | Op::UADDLV => {
                                        let sum: u64 = elems.iter().map(|&h| h as u64).sum();
                                        res[..8].copy_from_slice(&sum.to_le_bytes());
                                    }
                                    Op::SADDLV => {
                                        let sum: i64 = elems.iter().map(|&h| h as i16 as i64).sum();
                                        res[..8].copy_from_slice(&(sum as u64).to_le_bytes());
                                    }
                                    Op::UMAXV => {
                                        let m = elems.iter().copied().max().unwrap_or(0);
                                        res[..2].copy_from_slice(&m.to_le_bytes());
                                    }
                                    Op::UMINV => {
                                        let m = elems.iter().copied().min().unwrap_or(0);
                                        res[..2].copy_from_slice(&m.to_le_bytes());
                                    }
                                    Op::SMAXV => {
                                        let m = elems.iter().map(|&h| h as i16).max().unwrap_or(0) as u16;
                                        res[..2].copy_from_slice(&m.to_le_bytes());
                                    }
                                    Op::SMINV => {
                                        let m = elems.iter().map(|&h| h as i16).min().unwrap_or(0) as u16;
                                        res[..2].copy_from_slice(&m.to_le_bytes());
                                    }
                                    _ => {}
                                }
                            }
                            4 => {
                                let count = if is_64 { 2 } else { 4 };
                                let slice = &ctx.v[idx2];
                                let elems: Vec<u32> = (0..count).map(|i| u32::from_le_bytes(slice[i*4..i*4+4].try_into().unwrap())).collect();
                                match inst.op() {
                                    Op::ADDV | Op::UADDLV => {
                                        let sum: u64 = elems.iter().map(|&w| w as u64).sum();
                                        res[..8].copy_from_slice(&sum.to_le_bytes());
                                    }
                                    Op::SADDLV => {
                                        let sum: i64 = elems.iter().map(|&w| w as i32 as i64).sum();
                                        res[..8].copy_from_slice(&(sum as u64).to_le_bytes());
                                    }
                                    Op::UMAXV => {
                                        let m = elems.iter().copied().max().unwrap_or(0);
                                        res[..4].copy_from_slice(&m.to_le_bytes());
                                    }
                                    Op::UMINV => {
                                        let m = elems.iter().copied().min().unwrap_or(0);
                                        res[..4].copy_from_slice(&m.to_le_bytes());
                                    }
                                    Op::SMAXV => {
                                        let m = elems.iter().map(|&w| w as i32).max().unwrap_or(0) as u32;
                                        res[..4].copy_from_slice(&m.to_le_bytes());
                                    }
                                    Op::SMINV => {
                                        let m = elems.iter().map(|&w| w as i32).min().unwrap_or(0) as u32;
                                        res[..4].copy_from_slice(&m.to_le_bytes());
                                    }
                                    _ => {}
                                }
                            }
                            _ => {
                                let count = 2;
                                let slice = &ctx.v[idx2];
                                let elems: Vec<u64> = (0..count).map(|i| u64::from_le_bytes(slice[i*8..i*8+8].try_into().unwrap())).collect();
                                match inst.op() {
                                    Op::ADDV => {
                                        let sum: u64 = elems.iter().sum();
                                        res[..8].copy_from_slice(&sum.to_le_bytes());
                                    }
                                    Op::UMAXV => {
                                        let m = elems.iter().copied().max().unwrap_or(0);
                                        res[..8].copy_from_slice(&m.to_le_bytes());
                                    }
                                    Op::UMINV => {
                                        let m = elems.iter().copied().min().unwrap_or(0);
                                        res[..8].copy_from_slice(&m.to_le_bytes());
                                    }
                                    Op::SMAXV => {
                                        let m = elems.iter().map(|&d| d as i64).max().unwrap_or(0) as u64;
                                        res[..8].copy_from_slice(&m.to_le_bytes());
                                    }
                                    Op::SMINV => {
                                        let m = elems.iter().map(|&d| d as i64).min().unwrap_or(0) as u64;
                                        res[..8].copy_from_slice(&m.to_le_bytes());
                                    }
                                    _ => {}
                                }
                            }
                        }
                        ctx.v[idx1] = res;
                    }
                }
            }
            Op::FMOV => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    let val = get_operand_val(&ops[1], ctx);
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        set_reg_val(reg, val, ctx);
                    }
                }
            }
            Op::FCMP | Op::FCMPE => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Some(r1) = get_op_reg(&ops[0]) {
                        if let Some(idx1) = v_reg_idx(r1) {
                            let is_double = is_d_reg(r1);
                            let (n, z, c, v) = if is_double {
                                let v1 = f64::from_le_bytes(ctx.v[idx1][..8].try_into().unwrap());
                                let v2 = if let Some(r2) = get_op_reg(&ops[1]) {
                                    if let Some(idx2) = v_reg_idx(r2) {
                                        f64::from_le_bytes(ctx.v[idx2][..8].try_into().unwrap())
                                    } else { 0.0 }
                                } else { 0.0 };
                                if v1.is_nan() || v2.is_nan() {
                                    (false, false, true, true)
                                } else if v1 < v2 {
                                    (true, false, false, false)
                                } else if v1 == v2 {
                                    (false, true, true, false)
                                } else {
                                    (false, false, true, false)
                                }
                            } else {
                                let v1 = f32::from_le_bytes(ctx.v[idx1][..4].try_into().unwrap());
                                let v2 = if let Some(r2) = get_op_reg(&ops[1]) {
                                    if let Some(idx2) = v_reg_idx(r2) {
                                        f32::from_le_bytes(ctx.v[idx2][..4].try_into().unwrap())
                                    } else { 0.0 }
                                } else { 0.0 };
                                if v1.is_nan() || v2.is_nan() {
                                    (false, false, true, true)
                                } else if v1 < v2 {
                                    (true, false, false, false)
                                } else if v1 == v2 {
                                    (false, true, true, false)
                                } else {
                                    (false, false, true, false)
                                }
                            };
                            ctx.set_nzcv(n, z, c, v);
                        }
                    }
                }
            }
            Op::FADD | Op::FSUB | Op::FMUL | Op::FDIV => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    if let (Some(rd), Some(rn), Some(rm)) = (get_op_reg(&ops[0]), get_op_reg(&ops[1]), get_op_reg(&ops[2])) {
                        if let (Some(idxd), Some(idxn), Some(idxm)) = (v_reg_idx(rd), v_reg_idx(rn), v_reg_idx(rm)) {
                            if is_d_reg(rd) {
                                let vn = f64::from_le_bytes(ctx.v[idxn][..8].try_into().unwrap());
                                let vm = f64::from_le_bytes(ctx.v[idxm][..8].try_into().unwrap());
                                let res = match inst.op() {
                                    Op::FADD => vn + vm,
                                    Op::FSUB => vn - vm,
                                    Op::FMUL => vn * vm,
                                    Op::FDIV => vn / vm,
                                    _ => 0.0,
                                };
                                ctx.v[idxd][..8].copy_from_slice(&res.to_le_bytes());
                            } else if is_s_reg(rd) {
                                let vn = f32::from_le_bytes(ctx.v[idxn][..4].try_into().unwrap());
                                let vm = f32::from_le_bytes(ctx.v[idxm][..4].try_into().unwrap());
                                let res = match inst.op() {
                                    Op::FADD => vn + vm,
                                    Op::FSUB => vn - vm,
                                    Op::FMUL => vn * vm,
                                    Op::FDIV => vn / vm,
                                    _ => 0.0,
                                };
                                ctx.v[idxd][..4].copy_from_slice(&res.to_le_bytes());
                            }
                        }
                    }
                }
            }
            Op::FCVTZS | Op::FCVTZU => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let (Some(rd), Some(rn)) = (get_op_reg(&ops[0]), get_op_reg(&ops[1])) {
                        if let Some(idxn) = v_reg_idx(rn) {
                            let is_double = is_d_reg(rn);
                            let val_f64 = if is_double {
                                f64::from_le_bytes(ctx.v[idxn][..8].try_into().unwrap())
                            } else {
                                f32::from_le_bytes(ctx.v[idxn][..4].try_into().unwrap()) as f64
                            };
                            let int_val = if inst.op() == Op::FCVTZS {
                                val_f64 as i64 as u64
                            } else {
                                val_f64 as u64
                            };
                            set_reg_val(rd, int_val, ctx);
                        }
                    }
                }
            }
            Op::SCVTF | Op::UCVTF => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let (Some(rd), Some(_rn)) = (get_op_reg(&ops[0]), get_op_reg(&ops[1])) {
                        if let Some(idxd) = v_reg_idx(rd) {
                            let int_val = get_operand_val(&ops[1], ctx);
                            if is_d_reg(rd) {
                                let f_val = if inst.op() == Op::SCVTF {
                                    (int_val as i64) as f64
                                } else {
                                    int_val as f64
                                };
                                ctx.v[idxd][..8].copy_from_slice(&f_val.to_le_bytes());
                            } else if is_s_reg(rd) {
                                let f_val = if inst.op() == Op::SCVTF {
                                    (int_val as i64) as f32
                                } else {
                                    int_val as f32
                                };
                                ctx.v[idxd][..4].copy_from_slice(&f_val.to_le_bytes());
                            }
                        }
                    }
                }
            }
            Op::FNEG | Op::FABS | Op::FSQRT => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let (Some(rd), Some(rn)) = (get_op_reg(&ops[0]), get_op_reg(&ops[1])) {
                        if let (Some(idxd), Some(idxn)) = (v_reg_idx(rd), v_reg_idx(rn)) {
                            if is_d_reg(rd) {
                                let vn = f64::from_le_bytes(ctx.v[idxn][..8].try_into().unwrap());
                                let res = match inst.op() {
                                    Op::FNEG => -vn,
                                    Op::FABS => vn.abs(),
                                    Op::FSQRT => vn.sqrt(),
                                    _ => 0.0,
                                };
                                ctx.v[idxd][..8].copy_from_slice(&res.to_le_bytes());
                            } else if is_s_reg(rd) {
                                let vn = f32::from_le_bytes(ctx.v[idxn][..4].try_into().unwrap());
                                let res = match inst.op() {
                                    Op::FNEG => -vn,
                                    Op::FABS => vn.abs(),
                                    Op::FSQRT => vn.sqrt(),
                                    _ => 0.0,
                                };
                                ctx.v[idxd][..4].copy_from_slice(&res.to_le_bytes());
                            }
                        }
                    }
                }
            }
            Op::FCVT => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let (Some(rd), Some(rn)) = (get_op_reg(&ops[0]), get_op_reg(&ops[1])) {
                        if let (Some(idxd), Some(idxn)) = (v_reg_idx(rd), v_reg_idx(rn)) {
                            if is_d_reg(rd) && is_s_reg(rn) {
                                let s = f32::from_le_bytes(ctx.v[idxn][..4].try_into().unwrap());
                                let d = s as f64;
                                ctx.v[idxd][..8].copy_from_slice(&d.to_le_bytes());
                            } else if is_s_reg(rd) && is_d_reg(rn) {
                                let d = f64::from_le_bytes(ctx.v[idxn][..8].try_into().unwrap());
                                let s = d as f32;
                                ctx.v[idxd][..4].copy_from_slice(&s.to_le_bytes());
                            }
                        }
                    }
                }
            }
            Op::BIC | Op::BICS => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        let v1 = get_operand_val(&ops[1], ctx);
                        let v2 = get_operand_val(&ops[2], ctx);
                        let res = v1 & !v2;
                        set_reg_val(reg, res, ctx);
                        if inst.op() == Op::BICS {
                            let is_32 = is_w_reg(reg);
                            if is_32 {
                                let r32 = res as u32;
                                let n = (r32 as i32) < 0;
                                let z = r32 == 0;
                                ctx.set_nzcv(n, z, false, false);
                            } else {
                                let n = (res as i64) < 0;
                                let z = res == 0;
                                ctx.set_nzcv(n, z, false, false);
                            }
                        }
                    }
                }
            }
            Op::MVN => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        let v1 = get_operand_val(&ops[1], ctx);
                        set_reg_val(reg, !v1, ctx);
                    }
                }
            }
            Op::SXTW => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        let v = get_operand_val(&ops[1], ctx);
                        let val = ((v as i32) as i64) as u64;
                        set_reg_val(reg, val, ctx);
                    }
                }
            }
            Op::SXTH => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        let v = get_operand_val(&ops[1], ctx);
                        let val = ((v as i16) as i64) as u64;
                        set_reg_val(reg, val, ctx);
                    }
                }
            }
            Op::SXTB => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        let v = get_operand_val(&ops[1], ctx);
                        let val = ((v as i8) as i64) as u64;
                        set_reg_val(reg, val, ctx);
                    }
                }
            }
            Op::UXTW => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        let v = get_operand_val(&ops[1], ctx);
                        let val = (v as u32) as u64;
                        set_reg_val(reg, val, ctx);
                    }
                }
            }
            Op::UXTH => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        let v = get_operand_val(&ops[1], ctx);
                        let val = (v as u16) as u64;
                        set_reg_val(reg, val, ctx);
                    }
                }
            }
            Op::UXTB => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        let v = get_operand_val(&ops[1], ctx);
                        let val = (v as u8) as u64;
                        set_reg_val(reg, val, ctx);
                    }
                }
            }

            Op::UBFX => {
                let ops = inst.operands();
                if ops.len() >= 4 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        let v1 = get_operand_val(&ops[1], ctx);
                        let lsb = (get_operand_val(&ops[2], ctx) as usize) & 63;
                        let width = (get_operand_val(&ops[3], ctx) as usize) & 63;
                        let is_32 = is_w_reg(reg);
                        let n_bits = if is_32 { 32 } else { 64 };
                        let lsb = lsb % n_bits;
                        let mask = if width >= n_bits { !0u64 } else { (1u64 << width) - 1 };
                        let val = (v1 >> lsb) & mask;
                        if is_32 {
                            set_reg_val(reg, (val as u32) as u64, ctx);
                        } else {
                            set_reg_val(reg, val, ctx);
                        }
                    }
                }
            }
            Op::SBFX => {
                let ops = inst.operands();
                if ops.len() >= 4 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        let v1 = get_operand_val(&ops[1], ctx);
                        let lsb = (get_operand_val(&ops[2], ctx) as usize) & 63;
                        let width = (get_operand_val(&ops[3], ctx) as usize) & 63;
                        let is_32 = is_w_reg(reg);
                        let n_bits = if is_32 { 32 } else { 64 };
                        let lsb = lsb % n_bits;
                        let mask = if width >= n_bits { !0u64 } else { (1u64 << width) - 1 };
                        let raw = (v1 >> lsb) & mask;
                        let val = if width > 0 && (raw & (1u64 << (width - 1))) != 0 {
                            raw | !mask
                        } else {
                            raw
                        };
                        if is_32 {
                            set_reg_val(reg, (val as u32) as u64, ctx);
                        } else {
                            set_reg_val(reg, val, ctx);
                        }
                    }
                }
            }
            Op::UBFM => {
                let ops = inst.operands();
                if ops.len() >= 4 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        let v1 = get_operand_val(&ops[1], ctx);
                        let immr = get_operand_val(&ops[2], ctx);
                        let imms = get_operand_val(&ops[3], ctx);
                        let is_32 = is_w_reg(reg);
                        let n_bits = if is_32 { 32 } else { 64 };
                        let immr = (immr as usize) % n_bits;
                        let imms = (imms as usize) % n_bits;

                        let val = if imms >= immr {
                            let width = imms - immr + 1;
                            let mask = if width >= n_bits { !0u64 } else { (1u64 << width) - 1 };
                            (v1 >> immr) & mask
                        } else {
                            let width = imms + 1;
                            let mask = if width >= n_bits { !0u64 } else { (1u64 << width) - 1 };
                            let lsb = n_bits - immr;
                            (v1 & mask) << lsb
                        };

                        if is_32 {
                            set_reg_val(reg, (val as u32) as u64, ctx);
                        } else {
                            set_reg_val(reg, val, ctx);
                        }
                    }
                }
            }
            Op::SBFM => {
                let ops = inst.operands();
                if ops.len() >= 4 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        let v1 = get_operand_val(&ops[1], ctx);
                        let immr = get_operand_val(&ops[2], ctx);
                        let imms = get_operand_val(&ops[3], ctx);
                        let is_32 = is_w_reg(reg);
                        let n_bits = if is_32 { 32 } else { 64 };
                        let immr = (immr as usize) % n_bits;
                        let imms = (imms as usize) % n_bits;

                        let val = if imms >= immr {
                            let width = imms - immr + 1;
                            let mask = if width >= n_bits { !0u64 } else { (1u64 << width) - 1 };
                            let raw = (v1 >> immr) & mask;
                            let sign_bit = 1u64 << (width - 1);
                            if (raw & sign_bit) != 0 {
                                raw | !mask
                            } else {
                                raw
                            }
                        } else {
                            let width = imms + 1;
                            let mask = if width >= n_bits { !0u64 } else { (1u64 << width) - 1 };
                            let lsb = n_bits - immr;
                            (v1 & mask) << lsb
                        };

                        if is_32 {
                            set_reg_val(reg, (val as u32) as u64, ctx);
                        } else {
                            set_reg_val(reg, val, ctx);
                        }
                    }
                }
            }
            Op::BFM | Op::BFI | Op::BFXIL => {
                let ops = inst.operands();
                if ops.len() >= 4 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        let orig_dst = get_reg_val(reg, ctx);
                        let v1 = get_operand_val(&ops[1], ctx);
                        let immr = get_operand_val(&ops[2], ctx);
                        let imms = get_operand_val(&ops[3], ctx);
                        let is_32 = is_w_reg(reg);
                        let n_bits = if is_32 { 32 } else { 64 };
                        let mask_shift = n_bits - 1;
                        let immr = (immr & mask_shift) as u32;
                        let imms = (imms & mask_shift) as usize;

                        let rotated = if is_32 {
                            (v1 as u32).rotate_right(immr) as u64
                        } else {
                            v1.rotate_right(immr)
                        };
                        let bit_mask = if imms >= 63 { !0u64 } else { (1u64 << (imms + 1)) - 1 };
                        let val = (orig_dst & !bit_mask) | (rotated & bit_mask);
                        if is_32 {
                            set_reg_val(reg, (val as u32) as u64, ctx);
                        } else {
                            set_reg_val(reg, val, ctx);
                        }
                    }
                }
            }
            Op::LSL => {
                let ops = inst.operands();
                if pc == 0x400b10 {
                    tracing::info!("[LSL @ 0x400b10] ops.len()={} ops={:?}", ops.len(), ops);
                }
                if ops.len() >= 4 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        let v1 = get_operand_val(&ops[1], ctx);
                        let immr = get_operand_val(&ops[2], ctx);
                        let imms = get_operand_val(&ops[3], ctx);
                        let is_32 = is_w_reg(reg);
                        let n_bits = if is_32 { 32 } else { 64 };
                        let mask_shift = n_bits - 1;
                        let immr = (immr & mask_shift) as u32;
                        let imms = (imms & mask_shift) as usize;

                        let rotated = if is_32 {
                            (v1 as u32).rotate_right(immr) as u64
                        } else {
                            v1.rotate_right(immr)
                        };
                        let bit_mask = if imms >= 63 { !0u64 } else { (1u64 << (imms + 1)) - 1 };
                        let val = rotated & bit_mask;
                        tracing::info!("[LSL4 @ {:#x}] v1={:#x} immr={} imms={} rotated={:#x} mask={:#x} val={:#x}", pc, v1, immr, imms, rotated, bit_mask, val);
                        if is_32 {
                            set_reg_val(reg, (val as u32) as u64, ctx);
                        } else {
                            set_reg_val(reg, val, ctx);
                        }
                    }
                } else if ops.len() >= 3 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        let v1 = get_operand_val(&ops[1], ctx);
                        let shift = get_operand_val(&ops[2], ctx) as u32;
                        if is_w_reg(reg) {
                            let mask = 31;
                            set_reg_val(reg, ((v1 as u32).wrapping_shl(shift & mask)) as u64, ctx);
                        } else {
                            let mask = 63;
                            set_reg_val(reg, v1.wrapping_shl(shift & mask), ctx);
                        }
                    }
                }
            }
            Op::LSR => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        let v1 = get_operand_val(&ops[1], ctx);
                        let shift = get_operand_val(&ops[2], ctx) as u32;
                        if is_w_reg(reg) {
                            let mask = 31;
                            set_reg_val(reg, ((v1 as u32).wrapping_shr(shift & mask)) as u64, ctx);
                        } else {
                            let mask = 63;
                            set_reg_val(reg, v1.wrapping_shr(shift & mask), ctx);
                        }
                    }
                }
            }
            Op::ASR => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        let v1 = get_operand_val(&ops[1], ctx);
                        let shift = get_operand_val(&ops[2], ctx) as u32;
                        if is_w_reg(reg) {
                            let mask = 31;
                            set_reg_val(reg, (((v1 as i32) >> (shift & mask)) as u32) as u64, ctx);
                        } else {
                            let mask = 63;
                            set_reg_val(reg, ((v1 as i64) >> (shift & mask)) as u64, ctx);
                        }
                    }
                }
            }
            Op::ROR => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        let v1 = get_operand_val(&ops[1], ctx);
                        let shift = get_operand_val(&ops[2], ctx) as u32;
                        if is_w_reg(reg) {
                            let mask = 31;
                            set_reg_val(reg, (v1 as u32).rotate_right(shift & mask) as u64, ctx);
                        } else {
                            let mask = 63;
                            set_reg_val(reg, v1.rotate_right(shift & mask), ctx);
                        }
                    }
                }
            }
            Op::EXTR => {
                let ops = inst.operands();
                if ops.len() >= 4 {
                    if let Some(reg) = get_op_reg(&ops[0]) {
                        let vn = get_operand_val(&ops[1], ctx);
                        let vm = get_operand_val(&ops[2], ctx);
                        let lsb = get_operand_val(&ops[3], ctx) as u32;
                        if is_w_reg(reg) {
                            let concat = ((vn as u32 as u64) << 32) | (vm as u32 as u64);
                            let res = (concat >> lsb) as u32 as u64;
                            set_reg_val(reg, res, ctx);
                        } else {
                            let concat = ((vn as u128) << 64) | (vm as u128);
                            let res = (concat >> lsb) as u64;
                            set_reg_val(reg, res, ctx);
                        }
                    }
                }
            }
            Op::USHR | Op::SSHR => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    if let (Some(rd), Some(rn)) = (get_op_reg(&ops[0]), get_op_reg(&ops[1])) {
                        let shift = get_operand_val(&ops[2], ctx) as u32;
                        if let (Some(idxd), Some(idxn)) = (v_reg_idx(rd), v_reg_idx(rn)) {
                            let is_signed = inst.op() == Op::SSHR;
                            for elem in 0..4 {
                                let val = u32::from_le_bytes(ctx.v[idxn][elem * 4..(elem + 1) * 4].try_into().unwrap());
                                let res = if is_signed {
                                    ((val as i32) >> (shift & 31)) as u32
                                } else {
                                    val >> (shift & 31)
                                };
                                ctx.v[idxd][elem * 4..(elem + 1) * 4].copy_from_slice(&res.to_le_bytes());
                            }
                        }
                    }
                }
            }
            Op::ZIP1 | Op::ZIP2 => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    if let (Some(rd), Some(rn), Some(rm)) = (get_op_reg(&ops[0]), get_op_reg(&ops[1]), get_op_reg(&ops[2])) {
                        if let (Some(idxd), Some(idxn), Some(idxm)) = (v_reg_idx(rd), v_reg_idx(rn), v_reg_idx(rm)) {
                            let vn = ctx.v[idxn];
                            let vm = ctx.v[idxm];
                            let is_zip2 = inst.op() == Op::ZIP2;
                            let mut res = [0u8; 16];
                            let base = if is_zip2 { 2 } else { 0 };
                            let vn_0 = &vn[(base + 0) * 4..(base + 1) * 4];
                            let vm_0 = &vm[(base + 0) * 4..(base + 1) * 4];
                            let vn_1 = &vn[(base + 1) * 4..(base + 2) * 4];
                            let vm_1 = &vm[(base + 1) * 4..(base + 2) * 4];
                            res[0..4].copy_from_slice(vn_0);
                            res[4..8].copy_from_slice(vm_0);
                            res[8..12].copy_from_slice(vn_1);
                            res[12..16].copy_from_slice(vm_1);
                            ctx.v[idxd] = res;
                        }
                    }
                }
            }
            Op::XTN | Op::XTN2 => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let (Some(rd), Some(rn)) = (get_op_reg(&ops[0]), get_op_reg(&ops[1])) {
                        if let (Some(idxd), Some(idxn)) = (v_reg_idx(rd), v_reg_idx(rn)) {
                            let vn = ctx.v[idxn];
                            let mut res = [0u8; 16];
                            for elem in 0..4 {
                                let val = u32::from_le_bytes(vn[elem * 4..(elem + 1) * 4].try_into().unwrap());
                                res[elem * 2..(elem + 1) * 2].copy_from_slice(&(val as u16).to_le_bytes());
                            }
                            ctx.v[idxd] = res;
                        }
                    }
                }
            }
            Op::UMOV | Op::SMOV => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Some(rd) = get_op_reg(&ops[0]) {
                        let val = if let Some(rn) = get_op_reg(&ops[1]) {
                            if let Some(v_idx) = v_reg_idx(rn) {
                                let op_str = format!("{:?}", ops[1]);
                                let idx_elem = op_str.split("index:").nth(1).and_then(|s| s.trim().split(',').next()).and_then(|s| s.trim().parse::<usize>().ok()).unwrap_or(0);
                                if is_w_reg(rd) {
                                    let elem_val = u32::from_le_bytes(ctx.v[v_idx][(idx_elem * 4) % 16..((idx_elem * 4) % 16) + 4].try_into().unwrap());
                                    elem_val as u64
                                } else {
                                    let elem_val = u64::from_le_bytes(ctx.v[v_idx][(idx_elem * 8) % 16..((idx_elem * 8) % 16) + 8].try_into().unwrap());
                                    elem_val
                                }
                            } else {
                                get_operand_val(&ops[1], ctx)
                            }
                        } else {
                            get_operand_val(&ops[1], ctx)
                        };
                        set_reg_val(rd, val, ctx);
                    }
                }
            }
            Op::SXTL | Op::UXTL | Op::SXTL2 | Op::UXTL2 => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let (Some(rd), Some(rn)) = (get_op_reg(&ops[0]), get_op_reg(&ops[1])) {
                        if let (Some(idxd), Some(idxn)) = (v_reg_idx(rd), v_reg_idx(rn)) {
                            let vn = ctx.v[idxn];
                            let is_signed = inst.op() == Op::SXTL || inst.op() == Op::SXTL2;
                            let mut res = [0u8; 16];
                            for elem in 0..4 {
                                let val = u16::from_le_bytes(vn[elem * 2..(elem + 1) * 2].try_into().unwrap());
                                let ext = if is_signed {
                                    (val as i16) as i32 as u32
                                } else {
                                    val as u32
                                };
                                res[elem * 4..(elem + 1) * 4].copy_from_slice(&ext.to_le_bytes());
                            }
                            ctx.v[idxd] = res;
                        }
                    }
                }
            }
            Op::NOP | Op::BTI | Op::PACIASP | Op::AUTIASP | Op::PACIBSP | Op::AUTIBSP | Op::DMB | Op::DSB | Op::ISB => {
                // Do nothing (Pointer Authentication & BTI hint instructions)
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

    pub fn step_with_thunk_lookup<F>(
        ctx: &mut CpuContext,
        mem: &mut MemoryManager,
        thunk_lookup: F,
    ) -> Result<bool>
    where
        F: Fn(u64) -> Option<fn(&mut CpuContext, &mut MemoryManager) -> std::result::Result<(), String>>,
    {
        if ctx.exited {
            return Ok(false);
        }

        let pc = ctx.pc;
        if pc == 0x4cfee4 {
            tracing::info!("[Trace parse_common] key_ptr=0x{:x} field_pos={}", ctx.get_x(2), ctx.get_x(3));
        } else if pc == 0x4cffb4 {
            let s1 = mem.read_string(ctx.get_x(25)).unwrap_or_default();
            let s2 = mem.read_string(ctx.get_x(0)).unwrap_or_default();
            tracing::info!("[Trace parse_common strcmp] key={:?} field={:?}", String::from_utf8_lossy(&s1), String::from_utf8_lossy(&s2));
        } else if pc == 0x4d006c {
            tracing::info!("[Trace convert_to_struct]");
        }
        if let Some(thunk_fn) = thunk_lookup(pc) {
            thunk_fn(ctx, mem).map_err(|e| crate::Error::InterpreterError {
                pc,
                reason: format!("Thunk execution error at PC {:#x}: {}", pc, e),
            })?;
            if ctx.exited {
                return Ok(false);
            }
            if ctx.pc == pc {
                let lr = ctx.get_x(30);
                ctx.pc = lr;
            }
            return Ok(true);
        }

        Self::step(ctx, mem)
    }

    pub fn step_with_jit(
        ctx: &mut CpuContext,
        mem: &mut MemoryManager,
        jit_cache: &mut crate::jit::JitCache,
    ) -> Result<bool> {
        jit_cache.execute_block_chain(ctx, mem, 1)
    }

    pub fn run_with_jit(
        ctx: &mut CpuContext,
        mem: &mut MemoryManager,
        jit_cache: &mut crate::jit::JitCache,
    ) -> Result<()> {
        while !ctx.exited {
            if !jit_cache.execute_block_chain(ctx, mem, 1000)? {
                break;
            }
        }
        Ok(())
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
