use crate::bpf::BpfEvent;
use anyhow::Error;
use aya::{
    maps::{
        perf::{AsyncPerfEventArray, AsyncPerfEventArrayBuffer},
        MapRefMut,
    },
    util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use log::warn;
use std::{mem::size_of, sync::Arc};
use tokio::sync::mpsc::Sender;

pub struct Monitor {
    sender: Sender<BpfEvent>,
    queues: Vec<MonitoredQueue>,
}

impl Monitor {
    pub fn new(sender: Sender<BpfEvent>, queues: Vec<MonitoredQueue>) -> Self {
        Self { sender, queues }
    }

    pub fn launch(self, bpf: &Bpf) -> Result<(), Error> {
        let cpus = online_cpus()?;
        let mut event_queues = Vec::new();
        for queue in self.queues {
            let event_queue = AsyncPerfEventArray::try_from(bpf.map_mut(&queue.name)?)?;
            event_queues.push((event_queue, queue.event_builder));
        }
        for cpu in cpus {
            for (event_queue, event_builder) in &mut event_queues {
                Self::launch_process_events(cpu, event_queue, event_builder.clone(), self.sender.clone())?;
            }
        }
        Ok(())
    }

    fn launch_process_events(
        cpu: u32,
        queue: &mut AsyncPerfEventArray<MapRefMut>,
        event_builder: EventBuilder,
        sender: Sender<BpfEvent>,
    ) -> Result<(), Error> {
        let event_buffer = queue.open(cpu, None)?;
        tokio::task::spawn(async move { Self::process_events(event_buffer, event_builder, sender).await });
        Ok(())
    }

    async fn process_events(
        mut events_buffer: AsyncPerfEventArrayBuffer<MapRefMut>,
        event_builder: EventBuilder,
        sender: Sender<BpfEvent>,
    ) {
        let mut buffers = (0..1024).map(|_| BytesMut::with_capacity(event_builder.event_size)).collect::<Vec<_>>();
        loop {
            let events = events_buffer.read_events(&mut buffers).await.unwrap();
            if events.lost > 0 {
                warn!("Lost {} events", events.lost);
            }
            for buffer in &buffers[0..events.read] {
                let event = event_builder.build(buffer);
                if sender.send(event).await.is_err() {
                    warn!("Failed to send event to consumer");
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct EventBuilder {
    event_size: usize,
    builder: Arc<dyn Fn(&BytesMut) -> BpfEvent + Send + Sync>,
}

impl EventBuilder {
    fn build(&self, bytes: &BytesMut) -> BpfEvent {
        (self.builder)(bytes)
    }
}

pub struct MonitoredQueue {
    name: String,
    event_builder: EventBuilder,
}

impl MonitoredQueue {
    pub fn new<T>(name: &str) -> Self
    where
        BpfEvent: From<T>,
    {
        let name = name.into();
        let builder = Arc::new(|buffer: &BytesMut| {
            let ptr = buffer.as_ptr() as *const T;
            let event = unsafe { ptr.read_unaligned() };
            BpfEvent::from(event)
        });
        let event_builder = EventBuilder { event_size: size_of::<T>(), builder };
        Self { name, event_builder }
    }
}
