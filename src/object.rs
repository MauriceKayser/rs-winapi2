//! All object related Windows types.

/// Internal type for managing the `HANDLE` Windows type.
///
/// The trait `core::ops::Drop` is not implemented for this type, the internal users of this type
/// have to make sure they call the necessary Windows API to free the held resources.
#[derive(Clone)]
#[repr(C)]
pub(crate) struct Handle(isize);

impl Handle {
    // TODO: Remove once traits can have const fns (https://github.com/rust-lang/rfcs/pull/2632).
    /// `const` implementation of `core::convert::From<isize>`.
    ///
    /// To be used by functions which act upon pseudo-handles like `CURRENT_PROCESS = -1`.
    pub(crate) const fn from(value: isize) -> Self {
        Self(value)
    }

    /// Returns a boolean whether the given handle value is a pseudo handle (lower than `0`).
    pub(crate) const fn is_pseudo(&self) -> bool {
        self.0 < 0
    }
}