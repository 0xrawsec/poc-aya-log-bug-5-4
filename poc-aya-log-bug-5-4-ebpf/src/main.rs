#![no_std]
#![no_main]

use aya_bpf::{helpers::bpf_get_prandom_u32, macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::{error, info};

#[kprobe(name = "poc_aya_log_bug_5_4")]
pub fn poc_aya_log_bug_5_4(ctx: ProbeContext) -> u32 {
    match try_poc_aya_log_bug_5_4(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

pub enum MaybeEightBytes {
    EightBytes,
    NotEightBytes,
}

pub fn variable_str(b: bool) -> &'static str {
    if b {
        return "AAAAAAAA";
    }
    "A"
}

fn try_poc_aya_log_bug_5_4(ctx: ProbeContext) -> Result<u32, u32> {
    unsafe {
        error!(&ctx, "{}", variable_str(bpf_get_prandom_u32() % 2 == 0));
        Ok(0)
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
