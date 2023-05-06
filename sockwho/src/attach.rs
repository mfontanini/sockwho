use anyhow::Error;
use aya::{programs::TracePoint, Bpf};

/// Metadata about a tracepoint.
pub struct TracepointMeta {
    category: String,
    name: String,
}

/// Attaches probes.
pub struct ProbeAttacher<'a> {
    bpf: &'a mut Bpf,
    tracepoints: Vec<TracepointMeta>,
}

impl<'a> ProbeAttacher<'a> {
    pub fn attach_tracepoints(&mut self) -> Result<(), Error> {
        for tracepoint in &self.tracepoints {
            let program: &mut TracePoint = self.bpf.program_mut(&tracepoint.name).unwrap().try_into()?;
            program.load()?;
            program.attach(&tracepoint.category, &tracepoint.name)?;
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
    pub fn with_tracepoint<S1, S2>(mut self, category: S1, name: S2) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        let meta = TracepointMeta { category: category.into(), name: name.into() };
        self.attacher.tracepoints.push(meta);
        self
    }

    /// Builds the probe attacher.
    pub fn build(self) -> ProbeAttacher<'a> {
        self.attacher
    }
}
