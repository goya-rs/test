#![no_std]
#![no_main]

// FIXED version (goya-template issue #35).
// Use bpf_probe_read_user_buf: scalar return (Result<(), i32>) into a
// fixed-size buffer. No runtime-length copy anywhere -> no call to the
// global void memcpy/memset -> loads OK on kernel >= 5.18.

use aya_ebpf::{
    helpers::bpf_probe_read_user_buf,
    macros::{map, uprobe},
    maps::Array,
    programs::ProbeContext,
};

#[map]
pub static BUF: Array<[u8; 16]> = Array::with_max_entries(1, 0);

#[uprobe]
pub fn enter(ctx: ProbeContext) {
    let ptr = match ctx.arg::<*const u8>(0) {
        Some(p) => p,
        None => return,
    };
    let mptr = match BUF.get_ptr_mut(0) {
        Some(p) => p,
        None => return,
    };
    let v = unsafe { &mut *mptr };
    match unsafe { bpf_probe_read_user_buf(ptr, v) } {
        Ok(()) => {
            // use `v` here
        }
        Err(_) => return,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// Same license section the goya-template emits (makes the program GPL
// compatible so GPL helpers like bpf_probe_read_user can be called).
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
