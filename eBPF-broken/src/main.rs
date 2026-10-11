#![no_std]
#![no_main]

// BROKEN version (goya-template issue #35).
// bpf_probe_read_user_str_bytes returns a &[u8] with a RUNTIME length.
// Copying it (copy_from_slice) makes LLVM call the global fallback memcpy
// (which returns void) -> the kernel verifier (>= 5.18, function-by-function
// verification) rejects the program with:
//   "Global function memcpy() doesn't return scalar. Only those are supported."

use aya_ebpf::{
    helpers::bpf_probe_read_user_str_bytes,
    macros::{map, uprobe},
    maps::Array,
    programs::ProbeContext,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Data {
    pub str: [u8; 16],
    pub len: u32,
}

#[map]
pub static STATS: Array<Data> = Array::with_max_entries(1, 0);

#[uprobe]
pub fn enter(ctx: ProbeContext) {
    let ptr = match ctx.arg::<*const u8>(0) {
        Some(p) => p,
        None => return,
    };
    let mut tmp = [0u8; 16];
    let str_bytes = match unsafe { bpf_probe_read_user_str_bytes(ptr, &mut tmp) } {
        Ok(b) => b,
        Err(_) => return,
    };
    let mptr = match STATS.get_ptr_mut(0) {
        Some(p) => p,
        None => return,
    };
    let dst = unsafe { &mut *mptr };
    dst.len = str_bytes.len() as u32;
    // TRIGGER: runtime-length copy -> `call memcpy(dst, src, runtime_len)`
    // against aya-ebpf's global void memcpy.
    let n = str_bytes.len().min(dst.str.len());
    unsafe {
        dst.str[..n].copy_from_slice(&str_bytes[..n]);
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
