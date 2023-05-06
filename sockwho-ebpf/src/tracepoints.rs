use crate::context::Wrap;
use aya_bpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user},
    macros::map,
    maps::{HashMap, PerfEventArray},
    programs::TracePointContext,
};
use sockwho_common::{AddressFamily, HandlerResult, SockaddrEvent, Syscall};
use sockwho_macros::sockwho_tracepoint;

#[map]
static mut SOCKADDR_EVENTS: PerfEventArray<SockaddrEvent> = PerfEventArray::new(0);

#[map]
static mut PID_EVENT: HashMap<u64, SockaddrEvent> = HashMap::with_max_entries(1024, 0);

#[repr(C)]
struct SockaddrIn {
    family: u16,
    port: u16,
    address: [u8; 4],
}

#[repr(C)]
struct SockaddrIn6 {
    family: u16,
    port: u16,
    flow_info: u32,
    address: [u8; 16],
}

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[sockwho_tracepoint]
fn sys_enter_bind(ctx: TracePointContext) -> HandlerResult {
    let ctx = ctx.wrap();
    let pid = bpf_get_current_pid_tgid();
    let fd: i32 = ctx.read_field(16)?;
    if fd == -1 {
        return Ok(());
    }
    let sockaddr: *const u8 = ctx.read_field(24)?;
    let family: u16 = unsafe { bpf_probe_read_user(sockaddr as *const u16) }?;
    let family = match family {
        AF_INET => AddressFamily::Ipv4,
        AF_INET6 => AddressFamily::Ipv6,
        _ => return Err(1.into()),
    };
    let (address, port) = read_sockaddr(&family, sockaddr)?;
    let command = bpf_get_current_comm()?;

    let event = SockaddrEvent {
        pid: pid as u32,
        fd: fd as u32,
        address,
        port,
        family,
        syscall: Syscall::Bind,
        return_value: 0,
        command,
    };
    unsafe { PID_EVENT.insert(&pid, &event, 0) }?;

    Ok(())
}

#[sockwho_tracepoint]
fn sys_exit_bind(ctx: TracePointContext) -> HandlerResult {
    let ctx = ctx.wrap();
    let return_value = ctx.read_field(16)?;

    let pid = bpf_get_current_pid_tgid();
    let mut event = unsafe { &mut *PID_EVENT.get_ptr_mut(&pid).ok_or(1)? };
    event.return_value = return_value;

    unsafe { SOCKADDR_EVENTS.output(ctx.inner(), &event, 0) };

    Ok(())
}

fn read_sockaddr(family: &AddressFamily, sockaddr: *const u8) -> Result<([u8; 16], u16), i64> {
    match family {
        AddressFamily::Ipv4 => {
            let sockaddr = unsafe { bpf_probe_read_user(sockaddr as *const SockaddrIn) }?;
            let a = &sockaddr.address;
            let address = [a[0], a[1], a[2], a[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            Ok((address, sockaddr.port))
        }
        AddressFamily::Ipv6 => {
            let sockaddr = unsafe { bpf_probe_read_user(sockaddr as *const SockaddrIn6) }?;
            Ok((sockaddr.address, sockaddr.port))
        }
    }
}
