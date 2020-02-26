//! All object related Windows types.

pub mod security;

/// Official documentation: [ACCESS_MASK format](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-mask-format).
///
/// Specializations: [Access Rights and Access Masks](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-rights-and-access-masks).
#[allow(missing_docs)]
#[repr(u8)]
pub enum AccessMode {
    Delete,
    ReadControl,
    WriteDac,
    WriteOwner,
    Synchronize,
    SystemSecurity = 8,
    GenericAll = 12,
    GenericExecute,
    GenericWrite,
    GenericRead
}

/// Official documentation: [OBJECT_ATTRIBUTES struct](https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes).
#[repr(C)]
pub struct Attributes<'a> {
    length: u32,
    root_directory: Option<Handle>,
    object_name: Option<&'a crate::string::StringW<'a>>,
    flags: AttributeFlags,
    security_descriptor: Option<&'a security::Descriptor>,
    security_quality_of_service: Option<&'a security::QualityOfService>
}

impl<'a> Attributes<'a> {
    /// Creates a new instance.
    #[inline(always)]
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
}

/// The `Attributes` root directory field can refer to a file system directory or an object
/// directory in the object manager namespace.
#[allow(missing_docs)]
pub enum AttributeDirectory<'a> {
    File(&'a crate::file::Directory),
    Object(&'a Directory)
}

/// Official documentation: [OBJECT_ATTRIBUTES struct](https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes).
#[repr(C)]
pub struct AttributeFlags(bitfield::BitField32);

/// Official documentation: [OBJECT_ATTRIBUTES struct](https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes).
#[allow(missing_docs)]
#[repr(u8)]
pub enum AttributeFlag {
    Inherit = 1,
    Permanent = 4,
    Exclusive,
    CaseInsensitive,
    OpenIf,
    OpenLink,
    KernelHandle,
    ForceAccessCheck
}

impl AttributeFlags {
    /// Creates a new instance.
    #[inline(always)]
    pub const fn new() -> Self {
        Self(bitfield::BitField32::new())
    }

    /// Returns a modified variant with the flag set to the specified value.
    #[inline(always)]
    pub const fn set(&self, flag: AttributeFlag, value: bool) -> Self {
        Self(self.0.set_bit(flag as u8, value))
    }
}

/// Stores the necessary information to manipulate an object directory in the object manager
/// namespace.
#[repr(transparent)]
pub struct Directory(Handle);

/// Internal type for managing the `HANDLE` Windows type.
///
/// The trait `core::ops::Drop` is not implemented for this type, the internal users of this type
/// have to make sure they call the necessary Windows API to free the held resources.
// #[derive(Clone)]
#[repr(transparent)]
pub(crate) struct Handle(core::num::NonZeroIsize);

impl Handle {
    // TODO: Remove once traits can have const fns (https://github.com/rust-lang/rfcs/pull/2632).
    /// `const` implementation of `core::convert::From<isize>`.
    ///
    /// To be used by functions which act upon pseudo-handles like `CURRENT_PROCESS = -1`.
    #[inline(always)]
    pub(crate) const fn from(value: isize) -> Self {
        unsafe { Self(core::num::NonZeroIsize::new_unchecked(value)) }
    }

    /// Returns a boolean whether the given handle value is a pseudo handle (lower than `0`).
    #[inline(always)]
    pub(crate) const fn is_pseudo(&self) -> bool {
        self.0.get() < 0
    }
}

impl core::clone::Clone for Handle {
    fn clone(&self) -> Self {
        Self::from(self.0.get())
    }
}