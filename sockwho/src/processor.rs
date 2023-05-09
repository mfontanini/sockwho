use crate::bpf::BpfEvent;
use anyhow::anyhow;
use enum_primitive_derive::Primitive;
use log::warn;
use num_traits::FromPrimitive;
use sockwho_common::{AddressFamily, SockaddrEvent, SocketStateEvent, Syscall};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::sync::mpsc::{channel, Receiver, Sender};

pub struct EventProcessorConfig {
    pub channel_size: usize,
}

pub struct EventProcessor {
    sender: Sender<BpfEvent>,
    receiver: Receiver<BpfEvent>,
}

impl EventProcessor {
    pub fn new(config: EventProcessorConfig) -> Self {
        let (sender, receiver) = channel(config.channel_size);
        Self { sender, receiver }
    }

    pub fn sender(&self) -> Sender<BpfEvent> {
        self.sender.clone()
    }

    pub async fn run(mut self) {
        while let Some(event) = self.receiver.recv().await {
            let result = match event {
                BpfEvent::Sockaddr(event) => self.process_sockaddr_event(event),
                BpfEvent::SocketState(event) => self.process_socket_state_event(event),
            };
            if let Err(e) = result {
                warn!("Failed to handle event: {e}");
            }
        }
    }

    fn process_sockaddr_event(&self, event: SockaddrEvent) -> anyhow::Result<()> {
        let SockaddrEvent { pid, fd, address, port, family, syscall, return_value, command } = &event;
        let command = String::from_utf8_lossy(command);
        let syscall = syscall_name(syscall);
        let address = parse_address(family, address);
        let port = port.to_be();
        println!("{command}/{pid}/{fd} syscal::{syscall}({address}:{port}) = {return_value}");
        Ok(())
    }

    fn process_socket_state_event(&self, event: SocketStateEvent) -> anyhow::Result<()> {
        let SocketStateEvent {
            src_port,
            dst_port,
            family,
            _padding,
            old_state,
            new_state,
            pid,
            src_address,
            dst_address,
            command,
        } = &event;
        let command = String::from_utf8_lossy(command);
        let src_address = parse_address(family, src_address);
        let dst_address = parse_address(family, dst_address);
        let old_state = TcpState::from_u32(*old_state).ok_or_else(|| anyhow!("invalid old state"))?;
        let new_state = TcpState::from_u32(*new_state).ok_or_else(|| anyhow!("invalid new state"))?;
        println!(
            "{command}/{pid} socket::set_state({src_address}:{src_port} <-> {dst_address}:{dst_port}) {old_state:?} -> {new_state:?}"
        );
        Ok(())
    }
}

fn parse_address(family: &AddressFamily, address: &[u8; 16]) -> IpAddr {
    match family {
        AddressFamily::Ipv4 => IpAddr::from(Ipv4Addr::from([address[0], address[1], address[2], address[3]])),
        AddressFamily::Ipv6 => IpAddr::from(Ipv6Addr::from(*address)),
    }
}

fn syscall_name(syscall: &Syscall) -> &'static str {
    use Syscall::*;
    match syscall {
        Bind => "bind",
        Connect => "connect",
        RecvFrom => "recv_from",
        SendTo => "send_to",
    }
}

/// The state of a TCP connection.
#[derive(Clone, Debug, Primitive, PartialEq, Eq)]
pub enum TcpState {
    Established = 1,
    SynSent = 2,
    SynReceived = 3,
    FinWait1 = 4,
    FinWait2 = 5,
    TimeWait = 6,
    Close = 7,
    CloseWait = 8,
    LastAck = 9,
    Listen = 10,
    Closing = 11,
    NewSynReceived = 12,
}
