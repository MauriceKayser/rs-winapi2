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
    MaximumAllowed,
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
    IgnoreImpersonatedDeviceMap,
    DoNotReparse
}

/// Stores the necessary information to manipulate an object directory in the object manager
/// namespace.
#[repr(transparent)]
pub struct Directory(Handle);

/// Internal type for managing the `HANDLE` Windows type.
///
/// The trait `core::ops::Drop` is not implemented for this type, the internal users of this type
/// have to make sure they call the `close()` to free the held resources.
#[derive(Clone)]
#[repr(transparent)]
pub(crate) struct Handle(Id);

impl Handle {
    /// Constructs a new instance based on a raw primitive integer value.
    ///
    /// To be used by functions which act upon pseudo-handles like `CURRENT_PROCESS = -1`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(crate) const fn from(id: core::num::NonZeroUsize) -> Self {
        Self(Id::from(id))
    }

    /// Returns a boolean whether the given handle value is a pseudo handle (lower than `0`).
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(crate) const fn is_pseudo(&self) -> bool {
        self.0.0.get() > isize::MAX as usize
    }

    /// Closes the specified handle, if it is not a pseudo-handle.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(crate) fn close(self) {
        if self.is_pseudo() { return; }

        #[cfg(not(any(winapi = "native", winapi = "syscall")))]
        {
            let closed = unsafe { crate::dll::kernel32::CloseHandle(self) };
            debug_assert!(closed.into());
        }
        #[cfg(winapi = "native")]
        {
            let result = unsafe { crate::dll::ntdll::NtClose(self) };
            debug_assert!(result.is_none());
        }
        #[cfg(winapi = "syscall")]
        {
            let result = unsafe { crate::dll::syscall::NtClose(self) };
            debug_assert!(result.is_none());
        }
    }
}

/// Generic object identifiers, identical to kernel object handles.
///
/// The lower two bits are used as flags by some Windows APIs, the other bits store the actual
/// object index.
///
/// Unofficial documentation: [Raymond Chen: Why kernel `HANDLE` values are always a multiple of four](https://devblogs.microsoft.com/oldnewthing/20050121-00/?p=36633).
///
/// Unofficial documentation: [Raymond Chen: Why process and thread `ID` values are a multiples of four](https://devblogs.microsoft.com/oldnewthing/?p=23283).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct Id(core::num::NonZeroUsize);

impl Id {
    /// Constructs a new instance based on a raw primitive integer value.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(crate) const fn from(id: core::num::NonZeroUsize) -> Self {
        Self(id)
    }

    /// Returns the raw primitive integer value this id represents.
    #[allow(unused)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(crate) const fn value(&self) -> core::num::NonZeroUsize {
        self.0
    }

    /// Constructs a new instance.
    ///
    /// Returns `None` if the index is out of bounds.
    #[allow(unused)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(crate) const unsafe fn from_index(index: core::num::NonZeroUsize) -> Option<Self> {
        if index.get() >= 1 << core::mem::size_of::<usize>() * 8 - 2 { return None; }

        Some(Self(core::num::NonZeroUsize::new_unchecked(index.get() << 2)))
    }

    /// Returns the index this id represents.
    #[allow(unused)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(crate) const unsafe fn index(&self) -> core::num::NonZeroUsize {
        core::num::NonZeroUsize::new_unchecked(self.0.get() >> 2)
    }
}

impl core::fmt::Display for Id {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_is_pseudo() {
        assert!(Handle::from(unsafe {
            core::num::NonZeroUsize::new_unchecked(-1isize as usize)
        }).is_pseudo());
        assert!(!Handle::from(unsafe {
            core::num::NonZeroUsize::new_unchecked(1)
        }).is_pseudo());
    }

    #[test]
    fn id() {
        let id = unsafe {
            Id::from_index(core::num::NonZeroUsize::new_unchecked(25)).unwrap()
        };

        assert_eq!(&alloc::format!("{:?}", id), "Id(100)");
    }
}