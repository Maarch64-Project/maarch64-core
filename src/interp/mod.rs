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

fn get_operand_val(op: &Operand, ctx: &CpuContext) -> u64 {
    match op {
        Operand::Reg { reg, .. } => {
            if let Some(idx) = reg_idx(*reg) {
                ctx.get_x(idx)
            } else if *reg == Reg::SP {
                ctx.sp
            } else {
                0
            }
        }
        Operand::Imm64 { imm, .. } => imm_to_u64(imm),
        Operand::Imm32 { imm, .. } => imm_to_u64(imm),
        Operand::Label(imm) => imm_to_u64(imm),
        _ => 0,
    }
}

impl Interpreter {
    pub fn step(ctx: &mut CpuContext, mem: &mut MemoryManager) -> Result<bool> {
        let pc = ctx.pc;
        let code_bytes = mem.read(pc, 4)?;
        let opcode = u32::from_le_bytes(code_bytes.try_into().unwrap());

        let inst = Decoder::decode(opcode, pc)?;
        let next_pc = pc + 4;

        match inst.op() {
            Op::MOV | Op::MOVZ => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        let val = get_operand_val(&ops[1], ctx);
                        if let Some(idx) = reg_idx(reg) {
                            ctx.set_x(idx, val);
                        } else if reg == Reg::SP {
                            ctx.sp = val;
                        }
                    }
                }
            }
            Op::ADD => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        let v1 = get_operand_val(&ops[1], ctx);
                        let v2 = get_operand_val(&ops[2], ctx);
                        let res = v1.wrapping_add(v2);
                        if let Some(idx) = reg_idx(reg) {
                            ctx.set_x(idx, res);
                        } else if reg == Reg::SP {
                            ctx.sp = res;
                        }
                    }
                }
            }
            Op::SUB => {
                let ops = inst.operands();
                if ops.len() >= 3 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        let v1 = get_operand_val(&ops[1], ctx);
                        let v2 = get_operand_val(&ops[2], ctx);
                        let res = v1.wrapping_sub(v2);
                        if let Some(idx) = reg_idx(reg) {
                            ctx.set_x(idx, res);
                        } else if reg == Reg::SP {
                            ctx.sp = res;
                        }
                    }
                }
            }
            Op::LDR => {
                let ops = inst.operands();
                if ops.len() >= 2 {
                    if let Operand::Reg { reg, .. } = ops[0] {
                        if let Operand::Label(imm) = &ops[1] {
                            let target_addr = imm_to_u64(imm);
                            let val_bytes = mem.read(target_addr, 8)?;
                            let val = u64::from_le_bytes(val_bytes.try_into().unwrap());
                            if let Some(idx) = reg_idx(reg) {
                                ctx.set_x(idx, val);
                            }
                        }
                    }
                }
            }
            Op::SVC => {
                SyscallDispatcher::handle_syscall(ctx, mem)?;
            }
            _ => {
                tracing::warn!("Unimplemented opcode at {:#x}: {:?}", pc, inst);
            }
        }

        ctx.pc = next_pc;
        Ok(true)
    }

    pub fn run(ctx: &mut CpuContext, mem: &mut MemoryManager) -> Result<()> {
        while Interpreter::step(ctx, mem)? {}
        Ok(())
    }
}
