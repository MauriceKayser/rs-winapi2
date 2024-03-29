//! All historical Windows types.

/// For historical reasons a `bool` is returned as a `u32` by some Windows APIs.
///
/// Convert it from or to a real `bool` by calling the `core::convert::{From, Into}<bool>`
/// implementation.
#[repr(C)]
pub(crate) struct Boolean(u32);

impl Boolean {
    // TODO: Remove once traits can have const fns (https://github.com/rust-lang/rfcs/pull/2632).
    /// `const` implementation of `core::convert::Into<bool>`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(crate) const fn from(value: bool) -> Self {
        Self(value as u32)
    }

    // TODO: Remove once traits can have const fns (https://github.com/rust-lang/rfcs/pull/2632).
    /// `const` implementation of `core::convert::Into<bool>`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(crate) const fn as_bool(&self) -> bool {
        self.0 != 0
    }

    /// Collects the last `Status` value if this boolean is `false`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(crate) fn to_status_result(self) -> crate::error::StatusResult {
        (!self.as_bool()).then(|| ()).and_then(|_| crate::error::Status::last())
    }
}