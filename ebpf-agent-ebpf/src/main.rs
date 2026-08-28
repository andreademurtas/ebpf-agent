#![no_std]
#![no_main]

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

#[tracepoint]
pub fn handle_execve(_ctx: TracePointContext) -> u32 {
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
