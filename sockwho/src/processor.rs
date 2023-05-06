use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::bpf::BpfEvent;
use log::warn;
use sockwho_common::{AddressFamily, SockaddrEvent};
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
            };
            if let Err(e) = result {
                warn!("Failed to handle event: {e}");
            }
        }
    }

    fn process_sockaddr_event(&self, event: SockaddrEvent) -> anyhow::Result<()> {
        let SockaddrEvent { pid, fd, address, port, family, syscall, return_value, command } = &event;
        let command = String::from_utf8_lossy(command);
        let address = match family {
            AddressFamily::Ipv4 => IpAddr::from(Ipv4Addr::from([address[0], address[1], address[2], address[3]])),
            AddressFamily::Ipv6 => IpAddr::from(Ipv6Addr::from(*address)),
        };
        println!("{command} {syscall:?}({address}:{port}) = {return_value} [pid = {pid}, fd = {fd}]");
        Ok(())
    }
}
