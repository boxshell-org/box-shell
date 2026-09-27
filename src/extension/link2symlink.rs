//! link2symlink extension — port of extension/link2symlink/link2symlink.c (stub).

use crate::extension::Event;
use crate::sysnum::Sysnum;
use crate::tracee::Tracee;
use crate::Word;

#[derive(Default)]
pub struct Link2symlink;

impl Link2symlink {
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
