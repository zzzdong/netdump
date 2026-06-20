//! CBPF instruction types and constant definitions.

/// A single CBPF instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Instruction {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl Instruction {
    pub const fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        Self { code, jt, jf, k }
    }
}

// 指令类别
pub const BPF_LD: u16 = 0x00;
pub const BPF_LDX: u16 = 0x01;
pub const BPF_ST: u16 = 0x02;
pub const BPF_STX: u16 = 0x03;
pub const BPF_ALU: u16 = 0x04;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_RET: u16 = 0x06;
pub const BPF_MISC: u16 = 0x07;

// 操作数宽度
pub const BPF_W: u16 = 0x00;
pub const BPF_H: u16 = 0x08;
pub const BPF_B: u16 = 0x10;

// 寻址模式
pub const BPF_IMM: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_IND: u16 = 0x40;
pub const BPF_MEM: u16 = 0x60;
pub const BPF_LEN: u16 = 0x80;
pub const BPF_MSH: u16 = 0xa0;

// ALU 操作
pub const BPF_ADD: u16 = 0x00;
pub const BPF_SUB: u16 = 0x10;
pub const BPF_MUL: u16 = 0x20;
pub const BPF_DIV: u16 = 0x30;
pub const BPF_OR: u16 = 0x40;
pub const BPF_AND: u16 = 0x50;
pub const BPF_LSH: u16 = 0x60;
pub const BPF_RSH: u16 = 0x70;
pub const BPF_NEG: u16 = 0x80;
pub const BPF_MOD: u16 = 0x90;
pub const BPF_XOR: u16 = 0xa0;

// 跳转操作
pub const BPF_JA: u16 = 0x00;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JGT: u16 = 0x20;
pub const BPF_JGE: u16 = 0x30;
pub const BPF_JSET: u16 = 0x40;

// RET 源
pub const BPF_K: u16 = 0x00;
pub const BPF_X: u16 = 0x08;

// MISC
pub const BPF_TAX: u16 = 0x00;
pub const BPF_TXA: u16 = 0x80;

/// Non-zero value returned when a packet matches.
pub const CBPF_ACCEPT: u32 = 0xFFFF;
/// Zero value returned when a packet does not match.
pub const CBPF_REJECT: u32 = 0;

/// Build a `ld abs h` instruction.
pub fn ld_abs_h(k: u32) -> Instruction {
    Instruction::new(BPF_LD | BPF_H | BPF_ABS, 0, 0, k)
}

/// Build a `ld abs b` instruction.
pub fn ld_abs_b(k: u32) -> Instruction {
    Instruction::new(BPF_LD | BPF_B | BPF_ABS, 0, 0, k)
}

/// Build a `ld abs w` instruction.
pub fn ld_abs_w(k: u32) -> Instruction {
    Instruction::new(BPF_LD | BPF_W | BPF_ABS, 0, 0, k)
}

/// Build a `ld ind h` instruction (address = X + k).
pub fn ld_ind_h(k: u32) -> Instruction {
    Instruction::new(BPF_LD | BPF_H | BPF_IND, 0, 0, k)
}

/// Build a `ldx msh b` instruction: X = 4 * (packet[k] & 0x0f).
pub fn ldx_msh_b(k: u32) -> Instruction {
    Instruction::new(BPF_LDX | BPF_B | BPF_MSH, 0, 0, k)
}

/// Build a `jmp == k` conditional jump instruction.
pub fn jeq(k: u32) -> Instruction {
    Instruction::new(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, k)
}

/// Build a `jmp > k` conditional jump instruction.
pub fn jgt(k: u32) -> Instruction {
    Instruction::new(BPF_JMP | BPF_JGT | BPF_K, 0, 0, k)
}

/// Build a `jmp >= k` conditional jump instruction.
pub fn jge(k: u32) -> Instruction {
    Instruction::new(BPF_JMP | BPF_JGE | BPF_K, 0, 0, k)
}

/// Build a `ret #k` instruction.
pub fn ret_k(k: u32) -> Instruction {
    Instruction::new(BPF_RET | BPF_K, 0, 0, k)
}
