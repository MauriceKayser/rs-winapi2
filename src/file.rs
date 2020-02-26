//! All file system related Windows types.

/// Stores the necessary information to manipulate a file system directory object.
pub struct Directory(pub(crate) crate::object::Handle);