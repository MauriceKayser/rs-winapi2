//! All object related Windows types.

pub mod security;
pub mod synchronization;

/// Official documentation: [ACCESS_MASK format](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-mask-format).
///
/// Specializations: [Access Rights and Access Masks](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-rights-and-access-masks).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, bitfield::Flags)]
#[repr(u8)]
pub enum AccessMode {
    Delete = 16,
    ReadControl,
    WriteDac,
    WriteOwner,
    Synchronize,
    SystemSecurity = 24,
    GenericAll = 28,
    GenericExecute,
    GenericWrite,
    GenericRead
}

/// Official documentation: [OBJECT_ATTRIBUTES struct](https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes).
#[repr(C)]
pub struct Attributes<'a> {
    length: u32,
    /// A `Handle` with any access other than none is sufficient.
    pub(crate) root_directory: Option<Handle>,
    pub(crate) object_name: Option<&'a crate::string::StringW<'a>>,
    pub(crate) flags: AttributeFlags,
    pub(crate) security_descriptor: Option<&'a security::Descriptor>,
    pub(crate) security_quality_of_service: Option<&'a security::QualityOfService>
}

impl<'a> Attributes<'a> {
    /// Creates a new instance.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn new(
        root_directory: Option<&AttributeDirectory<'a>>,
        object_name: Option<&'a crate::string::StringW<'a>>,
        flags: AttributeFlags,
        security_descriptor: Option<&'a security::Descriptor>,
        security_quality_of_service: Option<&'a security::QualityOfService>
    ) -> Self {
        Self {
            length: core::mem::size_of::<Attributes>() as u32,
            root_directory: root_directory.map(|d| match d {
                AttributeDirectory::File(f) => f.0.clone(),
                AttributeDirectory::Object(o) => o.0.clone()
            }),
            object_name,
            flags,
            security_descriptor,
            security_quality_of_service
        }
    }

    /// Creates a new instance.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub const fn from_name(object_name: &'a crate::string::StringW<'a>) -> Self {
        Self {
            length: core::mem::size_of::<Attributes>() as u32,
            root_directory: None,
            object_name: Some(object_name),
            flags: AttributeFlags::new(),
            security_descriptor: None,
            security_quality_of_service: None
        }
    }
}

/// The `Attributes` root directory field can refer to a file system directory or an object
/// directory in the object manager namespace.
#[allow(missing_docs)]
pub enum AttributeDirectory<'a> {
    File(&'a crate::io::file::Directory),
    Object(&'a Directory)
}

/// Official documentation: [OBJECT_ATTRIBUTES struct](https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes).
#[bitfield::bitfield(32)]
#[derive(Copy, Clone, Debug, Display, Eq, PartialEq)]
pub struct AttributeFlags(pub AttributeFlag);

/// Official documentation: [OBJECT_ATTRIBUTES struct](https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, bitfield::Flags)]
#[repr(u8)]
pub enum AttributeFlag {
    Inherit = 1,
    Permanent = 4,
    Exclusive,
    ForceCaseInsensitive,
    OpenIf,
    OpenLink,
    KernelHandle,
    ForceAccessCheck,
    IgnoreImpersonatedDeviceMap
}

/// Stores the necessary information to manipulate an object directory in the object manager
/// namespace.
#[repr(transparent)]
pub struct Directory(Handle);

/// Internal type for managing the `HANDLE` Windows type.
///
/// The trait `core::ops::Drop` is not implemented for this type, the internal users of this type
/// have to make sure they call the necessary Windows API to free the held resources.
#[derive(Clone)]
#[repr(transparent)]
pub(crate) struct Handle(core::num::NonZeroIsize);

impl Handle {
    // TODO: Remove once traits can have const fns (https://github.com/rust-lang/rfcs/pull/2632).
    /// `const` implementation of `core::convert::From<core::num::NonZeroIsize>`.
    ///
    /// To be used by functions which act upon pseudo-handles like `CURRENT_PROCESS = -1`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(crate) const fn from(value: core::num::NonZeroIsize) -> Self {
        Self(value)
    }

    /// Returns a boolean whether the given handle value is a pseudo handle (lower than `0`).
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(crate) const fn is_pseudo(&self) -> bool {
        self.0.get() < 0
    }

    /// Closes the specified handle, if it is not a pseudo-handle.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(crate) fn close(self) {
        if self.is_pseudo() { return; }

        #[cfg(not(any(winapi = "native", winapi = "syscall")))]
        unsafe { crate::dll::kernel32::CloseHandle(self); }
        #[cfg(winapi = "native")]
        unsafe { crate::dll::ntdll::NtClose(self); }
        #[cfg(winapi = "syscall")]
        unsafe { crate::dll::syscall::NtClose(self); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_is_pseudo() {
        assert!(Handle(unsafe { core::num::NonZeroIsize::new_unchecked(-1) }).is_pseudo());
        assert!(!Handle(unsafe { core::num::NonZeroIsize::new_unchecked(1) }).is_pseudo());
    }
}