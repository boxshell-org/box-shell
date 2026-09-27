//! hidden_files extension — port of extension/hidden_files/hidden_files.c (stub).

use crate::extension::Event;
use crate::sysnum::Sysnum;
use crate::tracee::Tracee;
use crate::Word;

#[derive(Default)]
pub struct HiddenFiles;

impl HiddenFiles {
    pub fn callback(&mut self, _tracee: &mut Tracee, _event: &mut Event) -> i32 {
        0
    }
    pub fn filtered_sysnums(&self) -> &'static [Sysnum] {
        &[]
    }
    pub fn clone_for_child(&self, _clone_flags: Word) -> Self {
        Self::default()
    }
}
