//! All historical Windows types.

/// For historical reasons a `bool` is returned as a `u32` by some Windows APIs.
///
/// Convert it to a real `bool` by calling the `core::convert::Into<bool>` implementation.
#[repr(C)]
pub(crate) struct Boolean(u32);

impl Boolean {
    // TODO: Remove once traits can have const fns (https://github.com/rust-lang/rfcs/pull/2632).
    /// `const` implementation of `core::convert::Into<bool>`.
    pub(crate) const fn into(self) -> bool {
        self.0 != 0
    }
}