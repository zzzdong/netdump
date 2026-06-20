//! Simple CBPF assembler with label support, resolving relative jump offsets.

use std::collections::HashMap;

use crate::types::Instruction;

pub type LabelId = usize;

#[derive(Debug, Default)]
pub struct Assembler {
    insts: Vec<Instruction>,
    labels: HashMap<LabelId, usize>,
    pending: Vec<(usize, bool, LabelId)>,
    next_label: LabelId,
}

impl Assembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// 分配一个新标签。
    pub fn new_label(&mut self) -> LabelId {
        let id = self.next_label;
        self.next_label += 1;
        id
    }

    /// 下一条指令的索引。
    pub fn next_index(&self) -> usize {
        self.insts.len()
    }

    /// 发射一条指令。
    pub fn emit(&mut self, inst: Instruction) -> usize {
        let idx = self.insts.len();
        self.insts.push(inst);
        idx
    }

    /// 发射一条条件跳转，真/假分支分别跳转到对应标签。
    pub fn emit_jump(
        &mut self,
        inst: Instruction,
        true_label: LabelId,
        false_label: LabelId,
    ) -> usize {
        let idx = self.insts.len();
        self.pending.push((idx, true, true_label));
        self.pending.push((idx, false, false_label));
        self.insts.push(inst);
        idx
    }

    /// 将标签绑定到当前指令索引。
    pub fn place_label(&mut self, label: LabelId, index: usize) {
        self.labels.insert(label, index);
    }

    /// 解析所有标签引用，将目标地址转换为相对偏移。
    ///
    /// CBPF 中 jt/jf 是相对于下一条指令的偏移量，因此 offset = target - idx - 1。
    pub fn resolve(mut self) -> Vec<Instruction> {
        for (idx, is_jt, label) in self.pending {
            let target = *self.labels.get(&label).expect("存在未解析的标签");
            let offset = target
                .checked_sub(idx + 1)
                .expect("跳转目标必须位于当前指令之后");
            assert!(
                offset <= u8::MAX as usize,
                "跳转偏移 {offset} 超过 CBPF 最大值 255"
            );
            if is_jt {
                self.insts[idx].jt = offset as u8;
            } else {
                self.insts[idx].jf = offset as u8;
            }
        }
        self.insts
    }
}
