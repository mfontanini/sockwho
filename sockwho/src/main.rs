use anyhow::Error;
use aya::{include_bytes_aligned, Bpf};
use clap::{Parser, ValueEnum};
use sockwho::{
    attach::{ProbeAttacherBuilder, Tracepoint},
    monitor::{Monitor, MonitoredQueue},
    processor::{EventProcessor, EventProcessorConfig},
};
use sockwho_common::{SockaddrEvent, SocketStateEvent};

#[derive(Debug, Parser)]
struct Cli {
    /// The hooks to use.
    #[arg(value_enum, default_values_t = Hook::all())]
    hooks: Vec<Hook>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Hook {
    Bind,
    Connect,
    RecvFrom,
    SendTo,
    SocketState,
}

impl Hook {
    fn all() -> Vec<Hook> {
        vec![Hook::Bind, Hook::Connect, Hook::RecvFrom, Hook::SendTo, Hook::SocketState]
    }
}

impl From<Hook> for Tracepoint {
    fn from(hook: Hook) -> Self {
        use Hook::*;
        match hook {
            Bind => Tracepoint::syscall("bind"),
            Connect => Tracepoint::syscall("connect"),
            RecvFrom => Tracepoint::syscall("recvfrom"),
            SendTo => Tracepoint::syscall("sendto"),
            SocketState => Tracepoint::socket("inet_sock_set_state"),
        }
    }
}

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

    let cli = Cli::parse();

    let mut hooks = cli.hooks;
    hooks.sort();
    hooks.dedup();

    let mut bpf = load_bpf()?;
    let mut builder = ProbeAttacherBuilder::new(&mut bpf);
    for hook in hooks {
        builder = builder.with_tracepoint(hook.into());
    }
    let mut attacher = builder.build();
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
