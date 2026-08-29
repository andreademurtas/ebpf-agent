#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use ebpf_agent_common::ExecEvent;

const FILENAME_OFFSET: usize = 16;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint]
pub fn handle_execve(ctx: TracePointContext) -> u32 {
    match try_handle_execve(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_handle_execve(ctx: &TracePointContext) -> Result<(), i64> {
    let mut entry = match EVENTS.reserve::<ExecEvent>(0) {
        Some(entry) => entry,
        None => return Err(-1),
    };

    match unsafe { fill_event(ctx, entry.as_mut_ptr()) } {
        Ok(()) => {
            entry.submit(0);
            Ok(())
        }
        Err(e) => {
            entry.discard(0);
            Err(e)
        }
    }
}

unsafe fn fill_event(ctx: &TracePointContext, event: *mut ExecEvent) -> Result<(), i64> {
    (*event).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    (*event).uid = bpf_get_current_uid_gid() as u32;
    (*event).comm = bpf_get_current_comm().unwrap_or_default();

    (*event).filename = [0u8; ebpf_agent_common::FILENAME_LEN];
    let filename_ptr: *const u8 = ctx.read_at(FILENAME_OFFSET)?;
    bpf_probe_read_user_str_bytes(filename_ptr, &mut (*event).filename)?;
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
