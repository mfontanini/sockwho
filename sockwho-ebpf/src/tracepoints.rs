use crate::{context::ReadField, utils::as_pid};
use aya_bpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user},
    macros::map,
    maps::{HashMap, PerfEventArray},
    programs::TracePointContext,
};
use sockwho_common::{AddressFamily, HandlerResult, SockaddrEvent, SocketStateEvent, Syscall};
use sockwho_macros::sockwho_tracepoint;

#[map]
static mut SOCKADDR_EVENTS: PerfEventArray<SockaddrEvent> = PerfEventArray::new(0);

#[map]
static mut SOCKET_STATE_EVENTS: PerfEventArray<SocketStateEvent> = PerfEventArray::new(0);

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

struct ArgumentOffsets {
    fd: usize,
    sockaddr: usize,
}

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

// Control (bind/connect) syscall offsets.
static CONTROL_OFFSETS: ArgumentOffsets = ArgumentOffsets { fd: 16, sockaddr: 24 };

// IO (recvfrom/sendto) syscall offsets.
static IO_OFFSETS: ArgumentOffsets = ArgumentOffsets { fd: 16, sockaddr: 48 };

#[sockwho_tracepoint]
fn sys_enter_bind(ctx: TracePointContext) -> HandlerResult {
    syscall_enter(ctx, &CONTROL_OFFSETS, Syscall::Bind)
}

#[sockwho_tracepoint]
fn sys_enter_connect(ctx: TracePointContext) -> HandlerResult {
    syscall_enter(ctx, &CONTROL_OFFSETS, Syscall::Connect)
}

#[sockwho_tracepoint]
fn sys_enter_recvfrom(ctx: TracePointContext) -> HandlerResult {
    syscall_enter(ctx, &IO_OFFSETS, Syscall::RecvFrom)
}

#[sockwho_tracepoint]
fn sys_enter_sendto(ctx: TracePointContext) -> HandlerResult {
    syscall_enter(ctx, &IO_OFFSETS, Syscall::SendTo)
}

#[sockwho_tracepoint]
fn sys_exit_bind(ctx: TracePointContext) -> HandlerResult {
    syscall_exit(ctx)
}

#[sockwho_tracepoint]
fn sys_exit_connect(ctx: TracePointContext) -> HandlerResult {
    syscall_exit(ctx)
}

#[sockwho_tracepoint]
fn sys_exit_recvfrom(ctx: TracePointContext) -> HandlerResult {
    syscall_exit(ctx)
}

#[sockwho_tracepoint]
fn sys_exit_sendto(ctx: TracePointContext) -> HandlerResult {
    syscall_exit(ctx)
}

#[sockwho_tracepoint]
fn inet_sock_set_state(ctx: TracePointContext) -> HandlerResult {
    let pid = bpf_get_current_pid_tgid();
    let old_state = ctx.read_field(16)?;
    let new_state = ctx.read_field(20)?;
    let src_port = ctx.read_field(24)?;
    let dst_port = ctx.read_field(26)?;
    let family = match ctx.read_field::<u16>(28)? {
        AF_INET => AddressFamily::Ipv4,
        AF_INET6 => AddressFamily::Ipv6,
        _ => return Err(1.into()),
    };
    let (src_address, dst_address) = read_address_pair(&family, &ctx)?;
    let command = bpf_get_current_comm()?;

    let event = SocketStateEvent {
        src_port,
        dst_port,
        family,
        src_address,
        dst_address,
        old_state,
        new_state,
        pid: as_pid(pid),
        command,
        _padding: 0,
    };
    unsafe { SOCKET_STATE_EVENTS.output(&ctx, &event, 0) };

    Ok(())
}

fn syscall_enter(ctx: TracePointContext, offsets: &ArgumentOffsets, syscall: Syscall) -> HandlerResult {
    let pid = bpf_get_current_pid_tgid();
    let fd: i32 = ctx.read_field(offsets.fd)?;
    if fd == -1 {
        return Ok(());
    }
    let sockaddr: *const u8 = ctx.read_field(offsets.sockaddr)?;
    let family: u16 = unsafe { bpf_probe_read_user(sockaddr as *const u16) }?;
    let family = match family {
        AF_INET => AddressFamily::Ipv4,
        AF_INET6 => AddressFamily::Ipv6,
        _ => return Err(1.into()),
    };
    let (address, port) = read_sockaddr(&family, sockaddr)?;
    let command = bpf_get_current_comm()?;

    let event = SockaddrEvent { pid: as_pid(pid), fd: fd as u32, address, port, family, syscall, errno: 0, command };
    unsafe { PID_EVENT.insert(&pid, &event, 0) }?;

    Ok(())
}

fn syscall_exit(ctx: TracePointContext) -> HandlerResult {
    let return_value: i64 = ctx.read_field(16)?;

    let pid = bpf_get_current_pid_tgid();
    let mut event = unsafe { &mut *PID_EVENT.get_ptr_mut(&pid).ok_or(1)? };
    event.errno = return_value as i32;
    // TODO: check this
    event.command = bpf_get_current_comm()?;
    unsafe { SOCKADDR_EVENTS.output(&ctx, &event, 0) };
    unsafe { PID_EVENT.remove(&pid)? };

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

fn read_address_pair(family: &AddressFamily, ctx: &TracePointContext) -> Result<([u8; 16], [u8; 16]), u32> {
    match family {
        AddressFamily::Ipv4 => {
            let s: [u8; 4] = ctx.read_field(32)?;
            let d: [u8; 4] = ctx.read_field(36)?;
            Ok((
                [s[0], s[1], s[2], s[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                [d[0], d[1], d[2], d[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ))
        }
        AddressFamily::Ipv6 => Ok((ctx.read_field(40)?, ctx.read_field(56)?)),
    }
}
