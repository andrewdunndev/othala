#![allow(dead_code, unused_imports)]
use webauthn_rp::{Backup, BackupState};
fn f(s: BackupState) -> Backup {
    Backup::SingleDevice(s)
}
fn main() {}
