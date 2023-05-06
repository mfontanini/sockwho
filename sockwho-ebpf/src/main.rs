#![no_std]
#![no_main]

mod context;
mod tracepoints;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
