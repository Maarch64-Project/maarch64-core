pub use bad64::{decode, Instruction, Op, Operand, Reg};

pub struct Decoder;

impl Decoder {
    pub fn decode(opcode: u32, address: u64) -> Result<Instruction, crate::Error> {
        bad64::decode(opcode, address).map_err(|e| crate::Error::DecodeError {
            pc: address,
            reason: format!("{:?}", e),
        })
    }
}
