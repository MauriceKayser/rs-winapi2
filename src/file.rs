//! All file system related Windows types.

/// Stores the necessary information to manipulate a file system directory object.
pub struct Directory(pub(crate) crate::object::Handle);

/// Official documentation: [OVERLAPPED struct](https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-overlapped).
// TODO: Fill with actual data.
#[repr(C)]
pub(crate) struct Overlapped(u8);