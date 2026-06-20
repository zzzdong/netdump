//! CBPF virtual machine interpreter.

use netdump_filter::types::*;

/// CBPF virtual machine.
pub struct Vm;

impl Vm {
    /// Execute a CBPF program on a raw packet, returning whether it matched.
    pub fn exec(program: &[Instruction], packet: &[u8]) -> bool {
        let mut pc = 0usize;
        let mut a: u32 = 0;
        let mut x: u32 = 0;
        let mut mem = [0u32; 16];

        while pc < program.len() {
            let inst = program[pc];
            pc += 1;

            let class = inst.code & 0x07;
            match class {
                BPF_LD => {
                    let size = inst.code & 0x18;
                    let mode = inst.code & 0xE0;
                    match mode {
                        BPF_IMM => a = inst.k,
                        BPF_ABS => {
                            a = match size {
                                BPF_B => read_u8(packet, inst.k as usize) as u32,
                                BPF_H => read_u16(packet, inst.k as usize) as u32,
                                BPF_W => read_u32(packet, inst.k as usize),
                                _ => return false,
                            };
                        }
                        BPF_IND => {
                            let off = x as usize + inst.k as usize;
                            a = match size {
                                BPF_B => read_u8(packet, off) as u32,
                                BPF_H => read_u16(packet, off) as u32,
                                BPF_W => read_u32(packet, off),
                                _ => return false,
                            };
                        }
                        BPF_MEM => a = mem[(inst.k % 16) as usize],
                        BPF_LEN => a = packet.len() as u32,
                        _ => return false,
                    }
                }
                BPF_LDX => {
                    let mode = inst.code & 0xE0;
                    match mode {
                        BPF_IMM => x = inst.k,
                        BPF_MSH => x = ((read_u8(packet, inst.k as usize) & 0x0f) as u32) * 4,
                        BPF_MEM => x = mem[(inst.k % 16) as usize],
                        _ => return false,
                    }
                }
                BPF_ST => {
                    mem[(inst.k % 16) as usize] = a;
                }
                BPF_STX => {
                    mem[(inst.k % 16) as usize] = x;
                }
                BPF_ALU => {
                    let op = inst.code & 0xf0;
                    a = match op {
                        BPF_ADD => a.wrapping_add(inst.k),
                        BPF_SUB => a.wrapping_sub(inst.k),
                        BPF_MUL => a.wrapping_mul(inst.k),
                        BPF_DIV => {
                            if inst.k == 0 {
                                return false;
                            }
                            a / inst.k
                        }
                        BPF_OR => a | inst.k,
                        BPF_AND => a & inst.k,
                        BPF_LSH => a.wrapping_shl(inst.k),
                        BPF_RSH => a.wrapping_shr(inst.k),
                        BPF_MOD => {
                            if inst.k == 0 {
                                return false;
                            }
                            a % inst.k
                        }
                        BPF_XOR => a ^ inst.k,
                        BPF_NEG => a.wrapping_neg(),
                        _ => return false,
                    };
                }
                BPF_JMP => {
                    let op = inst.code & 0xf0;
                    if op == BPF_JA {
                        // 无条件跳转使用 k 作为相对偏移。
                        pc = pc.wrapping_add(inst.k as usize);
                        continue;
                    }
                    let cond = match op {
                        BPF_JEQ => a == inst.k,
                        BPF_JGT => a > inst.k,
                        BPF_JGE => a >= inst.k,
                        BPF_JSET => (a & inst.k) != 0,
                        _ => return false,
                    };
                    // jt/jf 为相对偏移（相对下一条指令）。
                    pc = if cond {
                        pc.wrapping_add(inst.jt as usize)
                    } else {
                        pc.wrapping_add(inst.jf as usize)
                    };
                }
                BPF_MISC => {
                    let op = inst.code & 0xf0;
                    match op {
                        BPF_TAX => x = a,
                        BPF_TXA => a = x,
                        _ => return false,
                    }
                }
                BPF_RET => {
                    let src = inst.code & 0x08;
                    let val = if src == BPF_K { inst.k } else { x };
                    return val != 0;
                }
                _ => return false,
            }
        }
        false
    }
}

fn read_u8(packet: &[u8], offset: usize) -> u8 {
    packet.get(offset).copied().unwrap_or(0)
}

fn read_u16(packet: &[u8], offset: usize) -> u16 {
    if offset + 2 > packet.len() {
        return 0;
    }
    u16::from_be_bytes([packet[offset], packet[offset + 1]])
}

fn read_u32(packet: &[u8], offset: usize) -> u32 {
    if offset + 4 > packet.len() {
        return 0;
    }
    u32::from_be_bytes([
        packet[offset],
        packet[offset + 1],
        packet[offset + 2],
        packet[offset + 3],
    ])
}
