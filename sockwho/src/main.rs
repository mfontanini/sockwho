use anyhow::Error;
use aya::{include_bytes_aligned, Bpf};
use clap::Parser;
use sockwho::{
    attach::ProbeAttacherBuilder,
    monitor::{Monitor, MonitoredQueue},
    processor::{EventProcessor, EventProcessorConfig},
};
use sockwho_common::{SockaddrEvent, SocketStateEvent};

#[derive(Debug, Parser)]
struct Opt {}

fn load_bpf() -> Result<Bpf, Error> {
    #[cfg(debug_assertions)]
    let bytes = include_bytes_aligned!("../../target/bpfel-unknown-none/debug/sockwho");

    #[cfg(not(debug_assertions))]
    let bytes = include_bytes_aligned!("../../target/bpfel-unknown-none/release/sockwho");

    Ok(Bpf::load(bytes)?)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();

    let mut bpf = load_bpf()?;

    let mut attacher = ProbeAttacherBuilder::new(&mut bpf)
        .with_tracepoint("syscalls", "sys_enter_bind")
        .with_tracepoint("syscalls", "sys_enter_connect")
        .with_tracepoint("syscalls", "sys_enter_recvfrom")
        .with_tracepoint("syscalls", "sys_enter_sendto")
        .with_tracepoint("syscalls", "sys_exit_bind")
        .with_tracepoint("syscalls", "sys_exit_connect")
        .with_tracepoint("syscalls", "sys_exit_recvfrom")
        .with_tracepoint("syscalls", "sys_exit_sendto")
        .with_tracepoint("sock", "inet_sock_set_state")
        .build();
    attacher.attach_tracepoints()?;

    let config = EventProcessorConfig { channel_size: 1024 };
    let processor = EventProcessor::new(config);
    let queues = vec![
        MonitoredQueue::new::<SockaddrEvent>("SOCKADDR_EVENTS"),
        MonitoredQueue::new::<SocketStateEvent>("SOCKET_STATE_EVENTS"),
    ];
    let monitor = Monitor::new(processor.sender(), queues);
    monitor.launch(&bpf)?;
    processor.run().await;

    Ok(())
}
