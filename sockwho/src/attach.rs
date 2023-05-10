use anyhow::{anyhow, Error};
use aya::{programs::TracePoint, Bpf};
use log::info;

/// Attaches probes.
pub struct ProbeAttacher<'a> {
    bpf: &'a mut Bpf,
    tracepoints: Vec<Tracepoint>,
}

impl<'a> ProbeAttacher<'a> {
    pub fn attach_tracepoints(&mut self) -> Result<(), Error> {
        for tracepoint in &self.tracepoints {
            for symbol in tracepoint.symbols() {
                info!("Attaching tracepoint '{symbol}");
                let program: &mut TracePoint =
                    self.bpf.program_mut(&symbol).ok_or_else(|| anyhow!("program '{symbol}' not found"))?.try_into()?;
                program.load()?;
                program.attach(tracepoint.category(), &symbol)?;
            }
        }
        Ok(())
    }
}

pub struct ProbeAttacherBuilder<'a> {
    attacher: ProbeAttacher<'a>,
}

impl<'a> ProbeAttacherBuilder<'a> {
    /// Construct a new builder for the given BPF instance.
    pub fn new(bpf: &'a mut Bpf) -> Self {
        let attacher = ProbeAttacher { bpf, tracepoints: Vec::new() };
        Self { attacher }
    }

    /// Adds a tracepoint to be attached.
    pub fn with_tracepoint(mut self, tracepoint: Tracepoint) -> Self {
        self.attacher.tracepoints.push(tracepoint);
        self
    }

    /// Builds the probe attacher.
    pub fn build(self) -> ProbeAttacher<'a> {
        self.attacher
    }
}

pub enum Tracepoint {
    Syscall(String),
    Socket(String),
}

impl Tracepoint {
    pub fn syscall<S: Into<String>>(name: S) -> Self {
        Self::Syscall(name.into())
    }

    pub fn socket<S: Into<String>>(name: S) -> Self {
        Self::Socket(name.into())
    }

    fn category(&self) -> &'static str {
        match self {
            Self::Syscall(_) => "syscalls",
            Self::Socket(_) => "sock",
        }
    }

    fn symbols(&self) -> Vec<String> {
        match self {
            Self::Syscall(name) => {
                vec![format!("sys_enter_{name}"), format!("sys_exit_{name}")]
            }
            Self::Socket(name) => vec![name.clone()],
        }
    }
}
