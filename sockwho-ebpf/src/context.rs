use aya_bpf::programs::TracePointContext;

pub struct TracePointContextWrapper {
    inner: TracePointContext,
}

impl TracePointContextWrapper {
    pub fn inner(&self) -> &TracePointContext {
        &self.inner
    }

    pub fn read_field<T>(&self, offset: usize) -> Result<T, u32> {
        unsafe { self.inner.read_at(offset) }.map_err(|_| 1_u32)
    }
}

pub trait Wrap {
    type Wrapper;

    fn wrap(self) -> Self::Wrapper;
}

impl Wrap for TracePointContext {
    type Wrapper = TracePointContextWrapper;

    fn wrap(self) -> Self::Wrapper {
        TracePointContextWrapper { inner: self }
    }
}
