#![no_std]

pub const COMM_LEN: usize = 16;
pub const FILENAME_LEN: usize = 256;

pub const EVENT_EXEC: u32 = 1;
pub const EVENT_FORK: u32 = 2;
pub const EVENT_EXIT: u32 = 3;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; COMM_LEN],
    pub filename: [u8; FILENAME_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ForkEvent {
    pub kind: u32,
    pub pid: u32,
    pub ppid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExitEvent {
    pub kind: u32,
    pub pid: u32,
}
