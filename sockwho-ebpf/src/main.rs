#![no_std]
#![no_main]

mod context;
mod tracepoints;
mod utils;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
