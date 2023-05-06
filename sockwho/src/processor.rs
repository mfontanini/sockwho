use crate::bpf::BpfEvent;
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
            match event {
                BpfEvent::Sockaddr(event) => {
                    let command = String::from_utf8_lossy(&event.command);
                    println!("{command}: {event:?}");
                }
            };
        }
    }
}
