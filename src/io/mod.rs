//! All input/output related Windows types.

pub mod file;

/// Official documentation: [OVERLAPPED struct](https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-overlapped).
// TODO: Implement.
#[repr(C)]
pub struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: crate::object::Handle
}