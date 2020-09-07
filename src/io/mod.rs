//! All input/output related Windows types.

pub mod file;

/// Official documentation: [OVERLAPPED struct](https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-overlapped).
#[repr(C)]
pub struct Overlapped<'a> {
    internal: usize,
    internal_high: usize,
    offset: u64,
    event: Option<crate::object::Handle>,
    _phantom: core::marker::PhantomData<&'a crate::object::Handle>
}

impl<'a> Overlapped<'a> {
    /// Creates a new instance and initializes the necessary fields for usage with (a-)synchronous
    /// object access.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn new(offset: u64, event: Option<&'a crate::object::synchronization::Event>) -> Self {
        Self {
            internal: 0, internal_high: 0,
            offset,
            event: event.map(|e| e.0.clone()),
            _phantom: core::marker::PhantomData
        }
    }
}