use aya_bpf::programs::TracePointContext;

pub trait ReadField {
    fn read_field<T>(&self, offset: usize) -> Result<T, u32>;
}

impl ReadField for TracePointContext {
    fn read_field<T>(&self, offset: usize) -> Result<T, u32> {
        unsafe { self.read_at(offset) }.map_err(|_| 1_u32)
    }
}
