//! All file system related Windows types.

pub mod info;
pub mod ntfs;

use enum_extensions::{FromPrimitive, Iterator};

bitfield::bit_field!(
    /// Official documentation: [FILE_ATTRIBUTE_* & FILE_FLAG_* enums](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).
    ///
    /// Official documentation: [FILE_ATTRIBUTE_* enum](https://docs.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants).
    #[derive(Copy, Clone, Eq, PartialEq)]
    pub Attributes: u32;
    flags:
        pub has + pub set: Attribute
);

// TODO: Security flags for Pipes.
/// Official documentation: [FILE_ATTRIBUTE_* & FILE_FLAG_* enums](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).
///
/// Official documentation: [FILE_ATTRIBUTE_* enum](https://docs.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, Iterator)]
#[repr(u8)]
pub enum Attribute {
    ReadOnly,
    Hidden,
    System,
    Directory = 4,
    Archive,
    Device,
    Normal,
    Temporary,
    SparseFile,
    ReParsePoint,
    Compressed,
    Offline,
    NotContentIndexed,
    Encrypted,
    IntegrityStream,
    Virtual,
    NoScrubData,
    RecallOnOpen,
    OpenNoRecall = 20,
    OpenReParsePoint,
    RecallOnDataAccess,
    SessionAware,
    PosixSemantics,
    BackupSemantics,
    DeleteOnClose,
    SequentialScan,
    RandomAccess,
    NoBuffering,
    Overlapped,
    WriteThrough
}

/// Official documentation: [GET_FILEEX_INFO_LEVELS enum](https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ne-minwinbase-get_fileex_info_levels).
#[derive(Copy, Clone, Debug, Iterator)]
#[repr(C)]
pub(crate) enum AttributeInfoLevel {
    Standard
}

/// Official documentation: [CreationDisposition enum](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, Iterator)]
#[repr(u32)]
pub enum CreationDispositionDirectoryKernel32 {
    CreateNew = 1,
    OpenExisting = 3,
    OpenAlways
}

/// Official documentation: [CreationDisposition enum](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, Iterator)]
#[repr(u32)]
pub enum CreationDispositionFileKernel32 {
    CreateNew = 1,
    CreateAlways,
    OpenExisting,
    OpenAlways,
    TruncateExisting
}

/// Official documentation: [CreationDisposition enum](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, Iterator)]
#[repr(u32)]
pub enum CreationDispositionDirectoryNtDll {
    OpenExisting = 1,
    CreateNew,
    OpenAlways
}

/// Official documentation: [CreationDisposition enum](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, Iterator)]
#[repr(u32)]
pub enum CreationDispositionFileNtDll {
    CreateAlways,
    OpenExisting,
    CreateNew,
    OpenAlways,
    TruncateExisting,
    TruncateAlways
}

bitfield::bit_field!(
    /// Official documentation: [CreationOptions enum](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile).
    ///
    /// Unofficial documentation: [FILE_* enum](https://github.com/processhacker/processhacker/blob/master/phnt/include/ntioapi.h).
    #[derive(Copy, Clone, Eq, PartialEq)]
    pub CreationOptions: u32;
    flags:
        pub has + pub set: CreationOption
);

/// Official documentation: [CreationOptions enum](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile).
///
/// Unofficial documentation: [FILE_* enum](https://github.com/processhacker/processhacker/blob/master/phnt/include/ntioapi.h).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, Iterator)]
#[repr(u8)]
pub enum CreationOption {
    DirectoryFile,
    WriteThrough,
    SequentialOnly,
    NoIntermediateBuffering,
    SynchronousIoAlert,
    SynchronousIoNonAlert,
    NonDirectoryFile,
    CreateTreeConnection,
    CompleteIfOpLocked,
    NoExtendedAttributesKnowledge,
    OpenForRecovery,
    RandomAccess,
    DeleteOnClose,
    OpenByFileId,
    OpenForBackupIntent,
    NoCompression,
    OpenRequiringOpLock,
    DisallowExclusive,
    SessionAware,
    ReserveOpFilter = 20,
    OpenReParsePoint,
    OpenNoRecall,
    OpenForFreeSpaceQuery
}

/// Stores the necessary information to manipulate a file system directory object.
pub struct Directory(pub(crate) crate::object::Handle);

impl Directory {
    /// Official documentation: [kernel32.CreateDirectoryW](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createdirectoryw).
    ///
    /// Official documentation: [kernel32.CreateFileW](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).
    ///
    /// Tries to create or open a file system directory object.
    ///
    /// This operation fails if `Attribute::BackupSemantics` is not set to `true`.
    ///
    /// Returns `BadFileType` in case the path points to a file.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn create_kernel32(
        path: &crate::string::Str,
        access_modes: DirectoryAccessModes,
        share_modes: ShareModes,
        security_descriptor: Option<&crate::object::security::Descriptor>,
        creation_disposition: CreationDispositionDirectoryKernel32,
        attributes: Attributes,
        template: Option<&Object>
    ) -> Result<(Self, Option<crate::error::Status>), crate::error::Status> {
        match creation_disposition {
            CreationDispositionDirectoryKernel32::CreateNew => {
                // Return early if an error occurs (f. e. directory already exists).
                if let Some(status) = unsafe { crate::dll::kernel32::CreateDirectoryW(
                    path.as_ptr(), security_descriptor
                ) }.to_status_result() { return Err(status); }

                Object::create_kernel32(
                    path, access_modes.0.value(), share_modes, security_descriptor,
                    CreationDispositionDirectoryKernel32::OpenExisting as u32,
                    attributes, template
                ).map(|result| (Self(result.0), result.1))
            },

            CreationDispositionDirectoryKernel32::OpenAlways => {
                // Try to create the directory.
                let status = unsafe { crate::dll::kernel32::CreateDirectoryW(
                    path.as_ptr(), security_descriptor
                ) }.to_status_result();

                match status {
                    // If it already exists, check if it is a directory or a file.
                    Some(status) if status == crate::error::StatusValue::AlreadyExists.into() => {
                        if !Object::attributes_kernel32(path)?.has(Attribute::Directory) {
                            return Err(crate::error::StatusValue::BadFileType.into());
                        }
                    },
                    Some(status) => return Err(status),
                    None => ()
                }

                Object::create_kernel32(
                    path, access_modes.0.value(), share_modes, security_descriptor,
                    creation_disposition as u32,
                    attributes, template
                ).map(|result| (Self(result.0), status))
            },

            CreationDispositionDirectoryKernel32::OpenExisting => {
                // If it already exists, check if it is a directory or a file.
                if !Object::attributes_kernel32(path)?.has(Attribute::Directory) {
                    return Err(crate::error::StatusValue::BadFileType.into());
                }

                Object::create_kernel32(
                    path, access_modes.0.value(), share_modes, security_descriptor,
                    creation_disposition as u32, attributes, template
                ).map(|result| (Self(result.0), result.1))
            }
        }
    }

    /// Official documentation: [ntdll.NtCreateFile](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile).
    ///
    /// Tries to create or open a file system directory object.
    ///
    /// Sets `CreationOption::DirectoryFile` to `true` and
    /// `CreationOption::NonDirectoryFile` to `false`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn create_ntdll(
        access_modes: DirectoryAccessModes,
        object_attributes: &crate::object::Attributes,
        attributes: Attributes,
        share_modes: ShareModes,
        creation_disposition: CreationDispositionDirectoryNtDll,
        creation_options: CreationOptions,
        extended_attributes: Option<(&crate::io::file::ntfs::ExtendedAttributesInformation, u32)>
    ) -> Result<(Self, IoStatus), crate::error::NtStatus> {
        // `allocation_size` is always ignored for directories by Windows.
        Object::create_ntdll(
            access_modes.0.value(), object_attributes, None, attributes,
            share_modes, creation_disposition as u32,
            creation_options
                .set(CreationOption::DirectoryFile, true)
                .set(CreationOption::NonDirectoryFile, false),
            extended_attributes
        ).map(|(handle, status)| (Self(handle), status))
    }

    /// Official documentation: [ntdll.NtCreateFile](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile).
    ///
    /// Tries to create or open a file system directory object.
    ///
    /// Sets `CreationOption::DirectoryFile` to `true` and
    /// `CreationOption::NonDirectoryFile` to `false`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn create_syscall(
        access_modes: DirectoryAccessModes,
        object_attributes: &crate::object::Attributes,
        attributes: Attributes,
        share_modes: ShareModes,
        creation_disposition: CreationDispositionDirectoryNtDll,
        creation_options: CreationOptions,
        extended_attributes: Option<(&crate::io::file::ntfs::ExtendedAttributesInformation, u32)>
    ) -> Result<(Self, IoStatus), crate::error::NtStatus> {
        // `allocation_size` is always ignored for directories by Windows.
        Object::create_syscall(
            access_modes.0.value(), object_attributes, None, attributes,
            share_modes, creation_disposition as u32,
            creation_options
                .set(CreationOption::DirectoryFile, true)
                .set(CreationOption::NonDirectoryFile, false),
            extended_attributes
        ).map(|(handle, status)| (Self(handle), status))
    }

    /// Official documentation: [ntdll.NtQueryInformationFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryinformationfile).
    ///
    /// Tries to get the file system attributes for a specified file system object.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn information_ntdll(
        &self
    ) -> Result<info::BasicNtDll, crate::error::NtStatus> {
        Object::object_information_ntdll(self.0.clone())
    }

    /// Official documentation: [ntdll.NtQueryInformationFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryinformationfile).
    ///
    /// Tries to get the file system attributes for a specified file system object.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn information_syscall(
        &self
    ) -> Result<info::BasicNtDll, crate::error::NtStatus> {
        Object::object_information_syscall(self.0.clone())
    }
}

impl core::ops::Drop for Directory {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn drop(&mut self) {
        self.0.clone().close();
    }
}

bitfield::bit_field!(
    /// Official documentation: [File Security and Access Rights](https://docs.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights).
    #[derive(Copy, Clone, Eq, PartialEq)]
    pub DirectoryAccessModes: u32;
    flags:
        pub has          + pub set:          DirectoryAccessMode,
        pub has_standard + pub set_standard: crate::object::AccessMode
);

/// Official documentation: [File Security and Access Rights](https://docs.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, Iterator)]
#[repr(u8)]
pub enum DirectoryAccessMode {
    List,
    AddFile,
    AddSubDirectory,
    ReadExtendedAttributes,
    WriteExtendedAttributes,
    Traverse,
    DeleteChild,
    ReadAttributes,
    WriteAttributes
}

/// Stores the necessary information to manipulate a file system file object.
pub struct File(pub(crate) crate::object::Handle);

impl File {
    /// Official documentation: [kernel32.CreateFileW](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).
    ///
    /// Tries to create or open a file system file object.
    ///
    /// Returns `BadFileType` in case the path points to a directory.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn create_kernel32(
        path: &crate::string::Str,
        access_modes: FileAccessModes,
        share_modes: ShareModes,
        security_descriptor: Option<&crate::object::security::Descriptor>,
        creation_disposition: CreationDispositionFileKernel32,
        attributes: Attributes,
        template: Option<&Object>
    ) -> Result<(Self, Option<crate::error::Status>), crate::error::Status> {
        if let Ok(attributes) = Object::attributes_kernel32(path) {
            if attributes.has(Attribute::Directory) {
                return Err(crate::error::StatusValue::BadFileType.into());
            }
        }

        Object::create_kernel32(
            path, access_modes.0.value(), share_modes,
            security_descriptor, creation_disposition as u32, attributes, template
        ).map(|result| (Self(result.0), result.1))
    }

    /// Official documentation: [ntdll.NtCreateFile](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile).
    ///
    /// Tries to create or open a file system file object.
    ///
    /// Sets `CreationOption::DirectoryFile` to `false` and
    /// `CreationOption::NonDirectoryFile` to `true`.
    ///
    /// At least on NTFS, the `allocation_size` parameter is rounded up to a 0x1000 boundary.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn create_ntdll(
        access_modes: FileAccessModes,
        object_attributes: &crate::object::Attributes,
        allocation_size: Option<&u64>,
        attributes: Attributes,
        share_modes: ShareModes,
        creation_disposition: CreationDispositionFileNtDll,
        creation_options: CreationOptions,
        extended_attributes: Option<(&crate::io::file::ntfs::ExtendedAttributesInformation, u32)>
    ) -> Result<(Self, IoStatus), crate::error::NtStatus> {
        Object::create_ntdll(
            access_modes.0.value(), object_attributes, allocation_size, attributes,
            share_modes, creation_disposition as u32,
            creation_options
                .set(CreationOption::DirectoryFile, false)
                .set(CreationOption::NonDirectoryFile, true),
            extended_attributes
        ).map(|(handle, status)| (Self(handle), status))
    }

    /// Official documentation: [ntdll.NtCreateFile](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile).
    ///
    /// Tries to create or open a file system file object.
    ///
    /// Sets `CreationOption::DirectoryFile` to `false` and
    /// `CreationOption::NonDirectoryFile` to `true`.
    ///
    /// At least on NTFS, the `allocation_size` parameter is rounded up to a 0x1000 boundary.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn create_syscall(
        access_modes: FileAccessModes,
        object_attributes: &crate::object::Attributes,
        allocation_size: Option<&u64>,
        attributes: Attributes,
        share_modes: ShareModes,
        creation_disposition: CreationDispositionFileNtDll,
        creation_options: CreationOptions,
        extended_attributes: Option<(&crate::io::file::ntfs::ExtendedAttributesInformation, u32)>
    ) -> Result<(Self, IoStatus), crate::error::NtStatus> {
        Object::create_syscall(
            access_modes.0.value(), object_attributes, allocation_size, attributes,
            share_modes, creation_disposition as u32,
            creation_options
                .set(CreationOption::DirectoryFile, false)
                .set(CreationOption::NonDirectoryFile, true),
            extended_attributes
        ).map(|(handle, status)| (Self(handle), status))
    }

    /// Official documentation: [ntdll.NtQueryInformationFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryinformationfile).
    ///
    /// Tries to get the file system attributes for a specified file system object.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn information_ntdll(
        &self
    ) -> Result<info::BasicNtDll, crate::error::NtStatus> {
        Object::object_information_ntdll(self.0.clone())
    }

    /// Official documentation: [ntdll.NtQueryInformationFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryinformationfile).
    ///
    /// Tries to get the file system attributes for a specified file system object.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn information_syscall(
        &self
    ) -> Result<info::BasicNtDll, crate::error::NtStatus> {
        Object::object_information_syscall(self.0.clone())
    }

    /// Official documentation: [kernel32.ReadFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile).
    ///
    /// Official documentation: [ntdll.NtReadFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntreadfile).
    ///
    /// Reads data from the specified file. Reads occur at the position specified by the file
    /// pointer if supported by the device.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn read<'a>(
        &self,
        buffer: &'a mut [core::mem::MaybeUninit<u8>]
    ) -> Result<&'a mut [u8], crate::error::Error> {
        #[cfg(not(any(winapi = "native", winapi = "syscall")))]
        { self.read_kernel32(buffer, None).map_err(|e| crate::error::Error::Status(e)) }
        #[cfg(winapi = "native")]
        { self.read_ntdll(None, buffer, None).map_err(|e| crate::error::Error::NtStatus(e)) }
        #[cfg(winapi = "syscall")]
        { self.read_syscall(None, buffer, None).map_err(|e| crate::error::Error::NtStatus(e)) }
    }

    // TODO: Enable this once array lengths support generic parameters (see [#43408](https://github.com/rust-lang/rust/issues/43408)).
    /*
    /// Official documentation: [kernel32.ReadFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile).
    ///
    /// Official documentation: [ntdll.NtReadFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntreadfile).
    ///
    /// Reads data from the specified file. Reads occur at the position specified by the file
    /// pointer if supported by the device.
    ///
    /// The user of this function has to make sure the `T` is FFI safe.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub unsafe fn read_generic<'a, T: Sized>(
        &self,
        buffer: &'a mut T
    ) -> Result<Result<&'a mut T, &'a mut [u8]>, crate::error::Error> {
        self.read(
            &mut *(buffer as *mut _ as *mut [core::mem::MaybeUninit<u8>; core::mem::size_of::<T>()])
        ).map(|result| crate::conversion::cast_mut(result).ok_or(result))
    }
    */

    /// Official documentation: [kernel32.ReadFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile).
    ///
    /// Reads data from the specified file. Reads occur at the position specified by the file
    /// pointer if supported by the device.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn read_kernel32<'a>(
        &self,
        buffer: &'a mut [core::mem::MaybeUninit<u8>],
        overlapped: Option<&mut crate::io::Overlapped>
    ) -> Result<&'a mut [u8], crate::error::Status> {
        let mut read_size = core::mem::MaybeUninit::uninit();
        unsafe {
            crate::dll::kernel32::ReadFile(
                self.0.clone(),
                buffer.as_mut_ptr() as *mut u8,
                buffer.len() as u32,
                read_size.as_mut_ptr(),
                overlapped
            ).to_status_result().map_or_else(|| Ok(
                &mut *(&mut buffer[..read_size.assume_init() as usize] as *mut _ as *mut [u8])
            ), |e| Err(e))
        }
    }

    // TODO: Enable this once array lengths support generic parameters (see [#43408](https://github.com/rust-lang/rust/issues/43408)).
    /*
    /// Official documentation: [kernel32.ReadFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile).
    ///
    /// Reads data from the specified file. Reads occur at the position specified by the file
    /// pointer if supported by the device.
    ///
    /// The user of this function has to make sure the `T` is FFI safe.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub unsafe fn read_generic_kernel32<'a, T: Sized>(
        &self,
        buffer: &'a mut T,
        overlapped: Option<&mut crate::io::Overlapped>
    ) -> Result<Result<&'a mut T, &'a mut [u8]>, crate::error::Status> {
        self.read_kernel32(
            &mut *(buffer as *mut _ as *mut [core::mem::MaybeUninit<u8>; core::mem::size_of::<T>()]),
            overlapped
        ).map(|result| crate::conversion::cast_mut(result).ok_or(result))
    }
    */

    /// Official documentation: [ntdll.NtReadFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntreadfile).
    ///
    /// Reads data from the specified file. Reads occur at the position specified by the file
    /// pointer if supported by the device.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn read_ntdll<'a>(
        &self,
        buffer: &'a mut [core::mem::MaybeUninit<u8>],
        offset: Option<&u64>,
        event: Option<&crate::object::synchronization::Event>
    ) -> Result<&'a mut [u8], crate::error::NtStatus> {
        let mut io_status_block = core::mem::MaybeUninit::uninit();

        unsafe { crate::dll::ntdll::NtReadFile(
            self.0.clone(),
            event.map(|e| e.0.clone()),
            0 as _, 0 as _,
            io_status_block.as_mut_ptr(),
            buffer.as_mut_ptr() as *mut u8,
            buffer.len() as u32,
            offset,
            None
        ).map(|e| Err(e)).unwrap_or_else(|| Ok(
            &mut *(&mut buffer[..io_status_block.assume_init().information as u32 as usize] as *mut _ as *mut [u8])
        )) }
    }

    // TODO: Enable this once array lengths support generic parameters (see [#43408](https://github.com/rust-lang/rust/issues/43408)).
    /*
    /// Official documentation: [ntdll.NtReadFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntreadfile).
    ///
    /// Reads data from the specified file. Reads occur at the position specified by the file
    /// pointer if supported by the device.
    ///
    /// The user of this function has to make sure the `T` is FFI safe.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub unsafe fn read_generic_ntdll<'a, T: Sized>(
        &self,
        buffer: &'a mut T,
        offset: Option<&u64>,
        event: Option<&crate::object::synchronization::Event>
    ) -> Result<Result<&'a mut T, &'a mut [u8]>, crate::error::NtStatus> {
        self.read_ntdll(
            &mut *(buffer as *mut _ as *mut [core::mem::MaybeUninit<u8>; core::mem::size_of::<T>()]),
            offset,
            event
        ).map(|result| crate::conversion::cast_mut(result).ok_or(result))
    }
    */

    /// Official documentation: [ntdll.NtReadFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntreadfile).
    ///
    /// Reads data from the specified file. Reads occur at the position specified by the file
    /// pointer if supported by the device.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn read_syscall<'a>(
        &self,
        buffer: &'a mut [core::mem::MaybeUninit<u8>],
        offset: Option<&u64>,
        event: Option<&crate::object::synchronization::Event>
    ) -> Result<&'a mut [u8], crate::error::NtStatus> {
        let mut io_status_block = core::mem::MaybeUninit::uninit();

        unsafe { crate::dll::syscall::NtReadFile(
            self.0.clone(),
            event.map(|e| e.0.clone()),
            0 as _, 0 as _,
            io_status_block.as_mut_ptr(),
            buffer.as_mut_ptr() as *mut u8,
            buffer.len() as u32,
            offset,
            None
        ).map(|e| Err(e)).unwrap_or_else(|| Ok(
            &mut *(&mut buffer[..io_status_block.assume_init().information as u32 as usize] as *mut _ as *mut [u8])
        )) }
    }

    // TODO: Enable this once array lengths support generic parameters (see [#43408](https://github.com/rust-lang/rust/issues/43408)).
    /*
    /// Official documentation: [ntdll.NtReadFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntreadfile).
    ///
    /// Reads data from the specified file. Reads occur at the position specified by the file
    /// pointer if supported by the device.
    ///
    /// The user of this function has to make sure the `T` is FFI safe.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub unsafe fn read_generic_syscall<'a, T: Sized>(
        &self,
        buffer: &'a mut T,
        offset: Option<&u64>,
        event: Option<&crate::object::synchronization::Event>
    ) -> Result<Result<&'a mut T, &'a mut [u8]>, crate::error::NtStatus> {
        self.read_syscall(
            &mut *(buffer as *mut _ as *mut [core::mem::MaybeUninit<u8>; core::mem::size_of::<T>()]),
            offset,
            event
        ).map(|result| crate::conversion::cast_mut(result).ok_or(result))
    }
    */

    /// Official documentation: [kernel32.WriteFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile).
    ///
    /// Official documentation: [ntdll.NtWriteFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntwritefile).
    ///
    /// Writes data to the specified file or input/output (I/O) device.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn write(
        &self,
        buffer: &[u8],
        offset_and_event: Option<(&u64, Option<&crate::object::synchronization::Event>)>
    ) -> Result<usize, crate::error::Error> {
        #[cfg(not(any(winapi = "native", winapi = "syscall")))]
        {
            let mut overlapped = offset_and_event.map(
                |(offset, event)| crate::io::Overlapped::new(*offset, event)
            );
            self.write_kernel32(buffer, overlapped.as_mut()).map_err(|e| crate::error::Error::Status(e))
        }
        #[cfg(winapi = "native")]
        { self.write_ntdll(
            buffer,
            offset_and_event.map(|o| o.0),
            offset_and_event.map(|e| e.1).flatten()
        ).map_err(|e| crate::error::Error::NtStatus(e)) }
        #[cfg(winapi = "syscall")]
        { self.write_syscall(
            buffer,
            offset_and_event.map(|o| o.0),
            offset_and_event.map(|e| e.1).flatten()
        ).map_err(|e| crate::error::Error::NtStatus(e)) }
    }

    // TODO: Enable this once array lengths support generic parameters (see [#43408](https://github.com/rust-lang/rust/issues/43408)).
    /*
    /// Official documentation: [kernel32.WriteFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile).
    ///
    /// Official documentation: [ntdll.NtWriteFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntwritefile).
    ///
    /// Writes data to the specified file or input/output (I/O) device.
    ///
    /// The user of this function has to make sure the `T` is FFI safe.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub unsafe fn write_generic<T: Sized>(
        &self,
        buffer: &T,
        offset_and_event: Option<(&u64, Option<&crate::object::synchronization::Event>)>
    ) -> Result<usize, crate::error::Error> {
        self.write(
            &mut *(buffer as *mut _ as *mut [u8; core::mem::size_of::<T>()]),
            offset_and_event
        )
    }
    */

    /// Official documentation: [kernel32.WriteFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile).
    ///
    /// Writes data to the specified file or input/output (I/O) device.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn write_kernel32(
        &self,
        buffer: &[u8],
        overlapped: Option<&mut crate::io::Overlapped>
    ) -> Result<usize, crate::error::Status> {
        let mut write_size = core::mem::MaybeUninit::uninit();
        unsafe {
            crate::dll::kernel32::WriteFile(
                self.0.clone(),
                buffer.as_ptr(),
                buffer.len() as u32,
                write_size.as_mut_ptr(),
                overlapped
            ).to_status_result().map_or_else(
                || Ok(write_size.assume_init() as usize), |e| Err(e)
            )
        }
    }

    // TODO: Enable this once array lengths support generic parameters (see [#43408](https://github.com/rust-lang/rust/issues/43408)).
    /*
    /// Official documentation: [kernel32.WriteFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile).
    ///
    /// Writes data to the specified file or input/output (I/O) device.
    ///
    /// The user of this function has to make sure the `T` is FFI safe.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub unsafe fn write_generic_kernel32<T: Sized>(
        &self,
        buffer: &T,
        overlapped: Option<&mut crate::io::Overlapped>
    ) -> Result<usize, crate::error::Status> {
        self.write_kernel32(
            &*(buffer as *const _ as *const [u8; core::mem::size_of::<T>()]), overlapped
        )
    }
    */

    /// Official documentation: [ntdll.NtWriteFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntwritefile).
    ///
    /// Writes data to an open file.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn write_ntdll(
        &self,
        buffer: &[u8],
        offset: Option<&u64>,
        event: Option<&crate::object::synchronization::Event>
    ) -> Result<usize, crate::error::NtStatus> {
        let mut io_status_block = core::mem::MaybeUninit::uninit();

        unsafe { crate::dll::ntdll::NtWriteFile(
            self.0.clone(),
            event.map(|e| e.0.clone()),
            0 as _, 0 as _,
            io_status_block.as_mut_ptr(),
            buffer.as_ptr(),
            buffer.len() as u32,
            offset,
            None
        ).map_or_else(
            || Ok(io_status_block.assume_init().information as u32 as usize), |e| Err(e)
        ) }
    }

    // TODO: Enable this once array lengths support generic parameters (see [#43408](https://github.com/rust-lang/rust/issues/43408)).
    /*
    /// Official documentation: [ntdll.NtWriteFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntwritefile).
    ///
    /// Writes data to an open file.
    ///
    /// The user of this function has to make sure the `T` is FFI safe.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub unsafe fn write_generic_ntdll<T: Sized>(
        &self,
        buffer: &T,
        offset: Option<&u64>,
        event: Option<&crate::object::synchronization::Event>
    ) -> Result<usize, crate::error::NtStatus> {
        self.write_ntdll(
            &*(buffer as *const _ as *const [u8; core::mem::size_of::<T>()]), offset, event
        )
    }
    */

    /// Official documentation: [ntdll.NtWriteFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntwritefile).
    ///
    /// Writes data to an open file.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn write_syscall(
        &self,
        buffer: &[u8],
        offset: Option<&u64>,
        event: Option<&crate::object::synchronization::Event>
    ) -> Result<usize, crate::error::NtStatus> {
        let mut io_status_block = core::mem::MaybeUninit::uninit();

        unsafe { crate::dll::syscall::NtWriteFile(
            self.0.clone(),
            event.map(|e| e.0.clone()),
            0 as _, 0 as _,
            io_status_block.as_mut_ptr(),
            buffer.as_ptr(),
            buffer.len() as u32,
            offset,
            None
        ).map_or_else(
            || Ok(io_status_block.assume_init().information as u32 as usize), |e| Err(e)
        ) }
    }

    // TODO: Enable this once array lengths support generic parameters (see [#43408](https://github.com/rust-lang/rust/issues/43408)).
    /*
    /// Official documentation: [ntdll.NtWriteFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntwritefile).
    ///
    /// Writes data to an open file.
    ///
    /// The user of this function has to make sure the `T` is FFI safe.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub unsafe fn write_generic_syscall<T: Sized>(
        &self,
        buffer: &T,
        offset: Option<&u64>,
        event: Option<&crate::object::synchronization::Event>
    ) -> Result<usize, crate::error::NtStatus> {
        self.write_syscall(
            &*(buffer as *const _ as *const [u8; core::mem::size_of::<T>()]), offset, event
        )
    }
    */
}

impl core::ops::Drop for File {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn drop(&mut self) {
        self.0.clone().close();
    }
}

bitfield::bit_field!(
    /// Official documentation: [File Security and Access Rights](https://docs.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights).
    #[derive(Copy, Clone, Eq, PartialEq)]
    pub FileAccessModes: u32;
    flags:
        pub has          + pub set:          FileAccessMode,
        pub has_standard + pub set_standard: crate::object::AccessMode
);

/// Official documentation: [File Security and Access Rights](https://docs.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, Iterator)]
#[repr(u8)]
pub enum FileAccessMode {
    ReadData,
    WriteData,
    AppendData,
    ReadExtendedAttributes,
    WriteExtendedAttributes,
    Execute,
    ReadAttributes = 7,
    WriteAttributes
}

/// Official documentation: [FileInformationClass enum](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_file_information_class).
#[allow(unused)]
#[derive(Copy, Clone, Debug, Iterator)]
#[repr(u32)]
pub(crate) enum Information {
    Directory = 1,
    FullDirectory,
    BothDirectory,
    Basic,
    Standard,
    Internal,
    Ea,
    Access,
    Name,
    Rename,
    Link,
    Names,
    Disposition,
    Position,
    FullEa,
    Mode,
    Alignment,
    All,
    Allocation,
    EndOfFile,
    AlternateName,
    Stream,
    Pipe,
    PipeLocal,
    PipeRemote,
    MailslotQuery,
    MailslotSet,
    Compression,
    ObjectId,
    Completion,
    MoveCluster,
    Quota,
    ReparsePoint,
    NetworkOpen,
    AttributeTag,
    Tracking,
    IdBothDirectory,
    IdFullDirectory,
    ValidDataLength,
    ShortName,
    IoCompletionNotification,
    IoStatusBlockRange,
    IoPriorityHint,
    SfioReserve,
    SfioVolume,
    HardLink,
    ProcessIdsUsingFile,
    NormalizedName,
    NetworkPhysicalName,
    IdGlobalTxDirectory,
    IsRemoteDevice,
    Unused,
    NumaNode,
    StandardLink,
    RemoteProtocol,

    // These are special versions of these operations (defined earlier)
    // which can be used by kernel mode drivers only to bypass security
    // access checks for Rename and HardLink operations.  These operations
    // are only recognized by the IOManager, a file system should never
    // receive these.
    RenameBypassAccessCheck,
    LinkBypassAccessCheck,
    // End of special information classes reserved for IOManager.

    VolumeName,
    Id,
    IdExtdDirectory,
    ReplaceCompletion,
    HardLinkFullId,
    IdExtdBothDirectory,
    DispositionEx,
    RenameEx,
    RenameExBypassAccessCheck,
    DesiredStorageClass,
    Stat,
    MemoryPartition,
    StatLx,
    CaseSensitive,
    LinkEx,
    LinkExBypassAccessCheck,
    StorageReserveId,
    CaseSensitiveForceAccessCheck,
}

/// Official documentation: [NtCreateFile status block results](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, Eq, FromPrimitive, Iterator, PartialEq)]
#[repr(u32)]
pub enum IoStatus {
    Superseded,
    Opened,
    Created,
    Overwritten,
    Exists,
    DoesNotExist
}

/// Official documentation: [IO_STATUS_BLOCK struct](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_status_block).
#[repr(C)]
pub(crate) struct IoStatusBlock {
    status: Option<crate::error::NtStatus>,
    information: *const u8
}

impl IoStatusBlock {
    /// Must only be used if the `IoStatusBlock` was used in a `NtCreateFile` or `NtOpenFile`
    /// operation.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn io_status(&self) -> Result<IoStatus, *const u8> {
        if self.information as usize > core::u32::MAX as usize { return Err(self.information); }
        core::convert::TryInto::<IoStatus>::try_into(self.information as usize as u32).map_err(
            |_| self.information
        )
    }
}

/// Contains either a directory or file object.
#[allow(missing_docs)]
pub enum Object {
    Directory(Directory),
    File(File)
}

impl Object {
    /// Official documentation: [kernel32.GetFileAttributesW](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileattributesw).
    ///
    /// Tries to get the file system attributes for a specified file or directory.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn attributes_kernel32(
        path: &crate::string::Str
    ) -> Result<Attributes, crate::error::Status> {
        Self::information_kernel32(path).map(|info| info.attributes)
    }

    /// Official documentation: [ntdll.NtQueryFullAttributesFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwqueryfullattributesfile).
    ///
    /// Tries to get the file system attributes for a specified file or directory.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn attributes_ntdll(
        object_attributes: &crate::object::Attributes
    ) -> Result<Attributes, crate::error::NtStatus> {
        Self::information_ntdll(object_attributes).map(|info| info.attributes)
    }

    /// Official documentation: [ntdll.NtQueryFullAttributesFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwqueryfullattributesfile).
    ///
    /// Tries to get the file system attributes for a specified file or directory.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn attributes_syscall(
        object_attributes: &crate::object::Attributes
    ) -> Result<Attributes, crate::error::NtStatus> {
        Self::information_syscall(object_attributes).map(|info| info.attributes)
    }

    /// Official documentation: [kernel32.CreateFileW](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).
    ///
    /// Tries to create or open a file or directory file system object.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn create_kernel32(
        path: &crate::string::Str,
        access_modes: u32,
        share_modes: ShareModes,
        security_descriptor: Option<&crate::object::security::Descriptor>,
        creation_disposition: u32,
        attributes: Attributes,
        template: Option<&Object>
    ) -> Result<(crate::object::Handle, Option<crate::error::Status>), crate::error::Status> {
        let handle = unsafe { crate::dll::kernel32::CreateFileW(
            path.as_ptr(),
            access_modes,
            share_modes,
            security_descriptor,
            creation_disposition,
            attributes,
            match template {
                Some(Object::Directory(d)) => Some(d.0.clone()),
                Some(Object::File(f)) => Some(f.0.clone()),
                _ => None
            }
        ) };

        let last = crate::error::Status::last();
        if !handle.is_pseudo() {
            Ok((handle, last))
        } else {
            Err(last.unwrap())
        }
    }

    /// Official documentation: [ntdll.NtCreateFile](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile).
    ///
    /// Tries to create or open a file or directory file system object.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn create_ntdll(
        access_modes: u32,
        object_attributes: &crate::object::Attributes,
        allocation_size: Option<&u64>,
        attributes: Attributes,
        share_modes: ShareModes,
        creation_disposition: u32,
        creation_options: CreationOptions,
        extended_attributes: Option<(&crate::io::file::ntfs::ExtendedAttributesInformation, u32)>
    ) -> Result<(crate::object::Handle, IoStatus), crate::error::NtStatus> {
        let mut handle = core::mem::MaybeUninit::uninit();
        let mut io_status_block = core::mem::MaybeUninit::uninit();

        let (ea, ea_size) = extended_attributes.map_or(
            (None, 0), |ea| (Some(ea.0), ea.1)
        );

        unsafe { crate::dll::ntdll::NtCreateFile(
            handle.as_mut_ptr(), access_modes, object_attributes, io_status_block.as_mut_ptr(),
            allocation_size, attributes, share_modes, creation_disposition, creation_options,
            ea, ea_size
        ).map(|e| Err(e)).unwrap_or_else(
            || Ok((handle.assume_init(), io_status_block.assume_init().io_status().unwrap()))
        ) }
    }

    /// Official documentation: [ntdll.NtCreateFile](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile).
    ///
    /// Tries to create or open a file or directory file system object.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn create_syscall(
        access_modes: u32,
        object_attributes: &crate::object::Attributes,
        allocation_size: Option<&u64>,
        attributes: Attributes,
        share_modes: ShareModes,
        creation_disposition: u32,
        creation_options: CreationOptions,
        extended_attributes: Option<(&crate::io::file::ntfs::ExtendedAttributesInformation, u32)>
    ) -> Result<(crate::object::Handle, IoStatus), crate::error::NtStatus> {
        let mut handle = core::mem::MaybeUninit::uninit();
        let mut io_status_block = core::mem::MaybeUninit::uninit();

        let (ea, ea_size) = extended_attributes.map_or(
            (None, 0), |ea| (Some(ea.0), ea.1)
        );

        unsafe { crate::dll::syscall::NtCreateFile(
            handle.as_mut_ptr(), access_modes, object_attributes, io_status_block.as_mut_ptr(),
            allocation_size, attributes, share_modes, creation_disposition, creation_options,
            ea, ea_size
        ).map(|e| Err(e)).unwrap_or_else(
            || Ok((handle.assume_init(), io_status_block.assume_init().io_status().unwrap()))
        ) }
    }

    /// Official documentation: [kernel32.GetFileAttributesExW](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileattributesexw).
    ///
    /// Tries to get the file system attributes for a specified file or directory file system object.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn information_kernel32(
        path: &crate::string::Str
    ) -> Result<info::BasicKernel32, crate::error::Status> {
        let mut information = core::mem::MaybeUninit::uninit();

        unsafe { crate::dll::kernel32::GetFileAttributesExW(
            path.as_ptr(), AttributeInfoLevel::Standard, information.as_mut_ptr() as *mut u8
        ).to_status_result().map_or_else(|| Ok(information.assume_init()), |e| Err(e)) }
    }

    /// Official documentation: [ntdll.NtQueryFullAttributesFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwqueryfullattributesfile).
    ///
    /// Tries to get the file system attributes for a specified file or directory file system object.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn information_ntdll(
        object_attributes: &crate::object::Attributes
    ) -> Result<info::BasicNtDll, crate::error::NtStatus> {
        let mut information = core::mem::MaybeUninit::uninit();

        unsafe { crate::dll::ntdll::NtQueryFullAttributesFile(
            object_attributes, information.as_mut_ptr()
        ).map(|e| Err(e)).unwrap_or_else(|| Ok(information.assume_init())) }
    }

    /// Official documentation: [ntdll.NtQueryFullAttributesFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwqueryfullattributesfile).
    ///
    /// Tries to get the file system attributes for a specified file or directory file system object.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn information_syscall(
        object_attributes: &crate::object::Attributes
    ) -> Result<info::BasicNtDll, crate::error::NtStatus> {
        let mut information = core::mem::MaybeUninit::uninit();

        unsafe { crate::dll::syscall::NtQueryFullAttributesFile(
            object_attributes, information.as_mut_ptr()
        ).map(|e| Err(e)).unwrap_or_else(|| Ok(information.assume_init())) }
    }

    /// Official documentation: [ntdll.NtQueryInformationFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryinformationfile).
    ///
    /// Tries to get the file system attributes for a specified file system object.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn object_information_ntdll(
        handle: crate::object::Handle
    ) -> Result<info::BasicNtDll, crate::error::NtStatus> {
        let mut information = core::mem::MaybeUninit::uninit();
        let mut io_status_block = core::mem::MaybeUninit::uninit();

        unsafe { crate::dll::ntdll::NtQueryInformationFile(
            handle,
            io_status_block.as_mut_ptr(),
            information.as_mut_ptr() as *mut u8,
            core::mem::size_of::<info::BasicNtDll>() as u32,
            Information::NetworkOpen
        ).map(|e| Err(e)).unwrap_or_else(|| Ok(information.assume_init())) }
    }

    /// Official documentation: [ntdll.NtQueryInformationFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryinformationfile).
    ///
    /// Tries to get the file system attributes for a specified file system object.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn object_information_syscall(
        handle: crate::object::Handle
    ) -> Result<info::BasicNtDll, crate::error::NtStatus> {
        let mut information = core::mem::MaybeUninit::uninit();
        let mut io_status_block = core::mem::MaybeUninit::uninit();

        unsafe { crate::dll::syscall::NtQueryInformationFile(
            handle,
            io_status_block.as_mut_ptr(),
            information.as_mut_ptr() as *mut u8,
            core::mem::size_of::<info::BasicNtDll>() as u32,
            Information::NetworkOpen
        ).map(|e| Err(e)).unwrap_or_else(|| Ok(information.assume_init())) }
    }
}

bitfield::bit_field!(
    /// Official documentation: [FILE_SHARE_* enum](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).
    #[derive(Copy, Clone, Eq, PartialEq)]
    pub ShareModes: u32;
    flags:
        pub has + pub set: ShareMode
);

/// Official documentation: [FILE_SHARE_* enum](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, Iterator)]
#[repr(u8)]
pub enum ShareMode {
    Read,
    Write,
    Delete
}

impl ShareModes {
    /// Creates a new instance with all flags set to `true`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub const fn all() -> Self {
        Self::new()
            .set(ShareMode::Read, true)
            .set(ShareMode::Write, true)
            .set(ShareMode::Delete, true)
    }
}

/// Official documentation: [FILETIME struct](https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime).
///
/// Official documentation: [Working with the FILETIME struct](https://support.microsoft.com/en-us/help/188768/info-working-with-the-filetime-structure).
///
/// Contains a value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC).
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub struct Time {
    time_low: u32,
    time_high: i32
}

impl Time {
    #[cfg_attr(not(debug_assertions), inline(always))]
    const fn value(&self) -> i64 {
        self.time_low as i64 | ((self.time_high as i64) << 32)
    }
}

impl core::fmt::Debug for Time {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        // TODO: Proper date time instead of integer output.
        f.write_str(&alloc::format!("{:?}", self.value()))
    }
}

impl core::cmp::PartialOrd for Time {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        core::cmp::PartialOrd::partial_cmp(&self.value(), &other.value())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::string::*;

    type NtCreateDirectory = fn(
        access_modes: DirectoryAccessModes,
        object_attributes: &crate::object::Attributes,
        attributes: Attributes,
        share_modes: ShareModes,
        creation_disposition: CreationDispositionDirectoryNtDll,
        creation_options: CreationOptions,
        extended_attributes: Option<(&crate::io::file::ntfs::ExtendedAttributesInformation, u32)>
    ) -> Result<(Directory, IoStatus), crate::error::NtStatus>;

    type NtCreateFile = fn(
        access_modes: FileAccessModes,
        object_attributes: &crate::object::Attributes,
        allocation_size: Option<&u64>,
        attributes: Attributes,
        share_modes: ShareModes,
        creation_disposition: CreationDispositionFileNtDll,
        creation_options: CreationOptions,
        extended_attributes: Option<(&crate::io::file::ntfs::ExtendedAttributesInformation, u32)>
    ) -> Result<(File, IoStatus), crate::error::NtStatus>;

    type NtQueryBasicInformationDirectory = fn(
        &Directory
    ) -> Result<info::BasicNtDll, crate::error::NtStatus>;

    type NtQueryBasicInformationFile = fn(
        &File
    ) -> Result<info::BasicNtDll, crate::error::NtStatus>;

    type NtQueryObjectAttributes = fn(
        object_attributes: &crate::object::Attributes
    ) -> Result<Attributes, crate::error::NtStatus>;

    type NtQueryObjectInformation = fn(
        object_attributes: &crate::object::Attributes
    ) -> Result<info::BasicNtDll, crate::error::NtStatus>;

    type NtReadFile = for<'a> fn(
        &File,
        buffer: &'a mut [core::mem::MaybeUninit<u8>],
        offset: Option<&u64>,
        event: Option<&crate::object::synchronization::Event>
    ) -> Result<&'a mut [u8], crate::error::NtStatus>;

    type NtWriteFile = fn(
        &File,
        buffer: &[u8],
        offset: Option<&u64>,
        event: Option<&crate::object::synchronization::Event>
    ) -> Result<usize, crate::error::NtStatus>;

    #[test]
    fn directory_create_kernel32_path() {
        let paths = &[
            // Non-existent directory.
            (
                "C:\\winapi2_this_must_not_exist.test\\\0",
                Err(crate::error::StatusValue::FileNotFound.into())
            ),
            // File in non-existent directory.
            (
                "C:\\winapi2_this_must_not_exist.test\\test.txt\0",
                Err(crate::error::StatusValue::PathNotFound.into())
            ),
            // Absolute directory.
            (
                "C:\\\0",
                Ok(None)
            ),
            // Absolute file.
            (
                "C:\\Windows\\System32\\ntdll.dll\0",
                Err(crate::error::StatusValue::BadFileType.into())
            ),
            // Relative directory.
            (
                "src\\\0",
                Ok(None)
            ),
            // Relative file.
            (
                "Cargo.toml\0",
                Err(crate::error::StatusValue::BadFileType.into())
            )
        ];

        for path in paths.iter() {
            let string = String::from(path.0);
            assert_eq!(Directory::create_kernel32(
                string.as_ref(),
                DirectoryAccessModes::new(),
                ShareModes::all(),
                None,
                CreationDispositionDirectoryKernel32::OpenExisting,
                Attributes::new().set(Attribute::BackupSemantics, true),
                None
            ).map(|r| r.1), path.1);
        }
    }

    /*
    // TODO: Implement use cases for directory handles.
    #[test]
    fn directory_create_kernel32_access_modes() {
        panic!("not implemented, yet");
    }

    // TODO: Find a clever way to test this.
    #[test]
    fn directory_create_kernel32_share_modes() {
        panic!("not implemented, yet");
    }

    // TODO: Implement security descriptor logic.
    #[test]
    fn directory_create_kernel32_security_descriptor() {
        panic!("not implemented, yet");
    }
    */

    #[test]
    fn directory_create_kernel32_creation_disposition() {
        let path = String::from("winapi2_directory_create_kernel32_creation_disposition\\\0");
        let path = path.as_ref();

        fn create(
            path: &Str,
            creation_disposition: CreationDispositionDirectoryKernel32,
            delete_on_close: bool
        ) -> Result<Option<crate::error::Status>, crate::error::Status> {
            Directory::create_kernel32(
                path,
                DirectoryAccessModes::new(),
                ShareModes::all(),
                None,
                creation_disposition,
                Attributes::new()
                    .set(Attribute::BackupSemantics, true)
                    .set(Attribute::DeleteOnClose, delete_on_close),
                None
            ).map(|r| r.1)
        }

        // CreateNew
        assert_eq!(
            create(
                path,
                CreationDispositionDirectoryKernel32::CreateNew,
                false
            ),
            Ok(None)
        );
        assert_eq!(
            create(
                path,
                CreationDispositionDirectoryKernel32::CreateNew,
                false
            ),
            Err(crate::error::StatusValue::AlreadyExists.into())
        );
        assert_eq!(
            create(
                path,
                CreationDispositionDirectoryKernel32::OpenExisting,
                true
            ),
            Ok(None)
        );

        // OpenExisting
        assert_eq!(
            create(
                path,
                CreationDispositionDirectoryKernel32::OpenExisting,
                false
            ),
            Err(crate::error::StatusValue::FileNotFound.into())
        );
        assert_eq!(
            create(
                path,
                CreationDispositionDirectoryKernel32::CreateNew,
                false
            ),
            Ok(None)
        );
        assert_eq!(
            create(
                path,
                CreationDispositionDirectoryKernel32::OpenExisting,
                true
            ),
            Ok(None)
        );

        // OpenAlways
        assert_eq!(
            create(
                path,
                CreationDispositionDirectoryKernel32::OpenAlways,
                false
            ),
            Ok(None)
        );
        assert_eq!(
            create(
                path,
                CreationDispositionDirectoryKernel32::OpenAlways,
                true
            ),
            Ok(Some(crate::error::StatusValue::AlreadyExists.into()))
        );
    }

    /*
    // TODO: Find a clever way to test this.
    #[test]
    fn directory_create_kernel32_attributes() {
        panic!("not implemented, yet");
    }
    */

    #[test]
    fn directory_create_kernel32_template() {
        fn create(
            path: &Str,
            creation_disposition: CreationDispositionDirectoryKernel32,
            template: Option<&Object>,
            delete_on_close: bool
        ) -> Directory {
            Directory::create_kernel32(
                path,
                DirectoryAccessModes::new(),
                ShareModes::all(),
                None,
                creation_disposition,
                Attributes::new()
                    .set(Attribute::BackupSemantics, true)
                    .set(Attribute::DeleteOnClose, delete_on_close),
                template
            ).unwrap().0
        }

        let windows = String::from("C:\\Windows\\\0");
        let windows_handle = create(
            windows.as_ref(), CreationDispositionDirectoryKernel32::OpenExisting,
            None, false
        );
        let windows_attributes = Object::attributes_kernel32(windows.as_ref()).unwrap();

        let local = String::from("winapi2_directory_create_kernel32_template\\\0");
        #[allow(unused)]
        let local_handle = create(
            local.as_ref(), CreationDispositionDirectoryKernel32::CreateNew,
            Some(&Object::Directory(windows_handle)), true
        );
        let local_attributes = Object::attributes_kernel32(local.as_ref()).unwrap();

        assert_eq!(windows_attributes, local_attributes);
    }

    /*
    // TODO: Implement use cases for directory handles.
    #[test]
    fn directory_create_nt_access_modes() {
        crate::init_syscall_ids();

        panic!("not implemented, yet");
    }
    */

    #[test]
    fn directory_create_nt_object_attributes() {
        crate::init_syscall_ids();

        fn create(
            f: &NtCreateDirectory,
            attributes: &crate::object::Attributes
        ) -> Result<IoStatus, crate::error::NtStatus> {
            f(
                DirectoryAccessModes::new()
                    .set(DirectoryAccessMode::List, true),
                attributes,
                Attributes::new(),
                ShareModes::all(),
                CreationDispositionDirectoryNtDll::OpenExisting,
                CreationOptions::new(),
                None
            ).map(|r| r.1)
        }

        for f in &[Directory::create_ntdll, Directory::create_syscall] {
            let mut attributes = crate::object::Attributes::new(
                None,
                None,
                crate::object::AttributeFlags::new(),
                None,
                None
            );

            assert_eq!(create(f, &attributes), Err(crate::error::NtStatusValue::ObjectPathSyntaxBad.into()));

            // object_name
            let windows = String::from(r"\??\C:\Windows\");
            let windows = StringW::from(windows.as_ref());
            attributes.object_name = Some(&windows);

            assert_eq!(create(f, &attributes), Ok(IoStatus::Opened));

            // root_directory
            let windows_attributes = crate::object::Attributes::from_name(&windows);
            let windows_handle = f(
                DirectoryAccessModes::new().set(DirectoryAccessMode::List, true),
                &windows_attributes,
                Attributes::new(),
                ShareModes::all(),
                CreationDispositionDirectoryNtDll::OpenExisting,
                CreationOptions::new(),
                None,
            ).unwrap();
            attributes.root_directory = Some((windows_handle.0).0.clone());
            let system32_local = String::from(r"System32\");
            let system32_local = StringW::from(system32_local.as_ref());
            attributes.object_name = Some(&system32_local);

            assert_eq!(create(f, &attributes), Ok(IoStatus::Opened));

            attributes.root_directory = None;

            // flags
            {
                // TODO: Check `Inherit` once process creation and handle enumeration is implemented.
                // TODO: Is `Permanent` usable in user mode?
                // TODO: Check `Exclusive` once process creation is implemented.

                // ForceCaseInsensitive
                let windows_cased = String::from(r"\??\C:\WiNdOwS\");
                let windows_cased = StringW::from(windows_cased.as_ref());
                attributes.object_name = Some(&windows_cased);

                // NTFS is case insensitive by default, so this assertion does not work.
                // assert_eq!(create(&attributes), Err(crate::error::NtStatusValue::ObjectNameNotFound.into()));

                attributes.flags = attributes.flags.set(
                    crate::object::AttributeFlag::ForceCaseInsensitive, true
                );
                assert_eq!(create(f, &attributes), Ok(IoStatus::Opened));

                attributes.flags = attributes.flags.set(
                    crate::object::AttributeFlag::ForceCaseInsensitive, false
                );
                attributes.object_name = Some(&windows);

                // TODO: Understand Microsoft's description and test `OpenIf`.
                // TODO: Check `OpenLink` once creating symbolic links is implemented.
                // TODO: Are `KernelHandle` and `ForceAccessCheck` testable in user mode?
                // TODO: Check `IgnoreImpersonatedDeviceMap` somehow.
            }

            // security_descriptor
            // TODO: Implement security descriptor logic.

            // security_quality_of_service
            // TODO: Implement security descriptor logic.
        }
    }

    /*
    // TODO: Find a clever way to test this.
    #[test]
    fn directory_create_nt_attributes() {
        crate::init_syscall_ids();

        panic!("not implemented, yet");
    }

    // TODO: Find a clever way to test this.
    #[test]
    fn directory_create_nt_share_modes() {
        crate::init_syscall_ids();

        panic!("not implemented, yet");
    }
    */

    #[test]
    fn directory_create_nt_creation_disposition() {
        crate::init_syscall_ids();

        let path = String::from(r"\??\C:\winapi2_directory_create_nt_creation_disposition\");
        let path = StringW::from(path.as_ref());

        fn create(
            f: &NtCreateDirectory,
            object_name: &StringW,
            creation_disposition: CreationDispositionDirectoryNtDll,
            delete_on_close: bool
        ) -> Result<IoStatus, crate::error::NtStatus> {
            let attributes = crate::object::Attributes::from_name(object_name);
            f(
                DirectoryAccessModes::new()
                    .set(DirectoryAccessMode::List, true)
                    .set_standard(crate::object::AccessMode::Delete, delete_on_close),
                &attributes,
                Attributes::new(),
                ShareModes::all(),
                creation_disposition,
                CreationOptions::new()
                    .set(CreationOption::DeleteOnClose, delete_on_close),
                None
            ).map(|r| r.1)
        }

        for f in &[Directory::create_ntdll, Directory::create_syscall] {
            // OpenExisting
            assert_eq!(
                create(
                    f,
                    &path,
                    CreationDispositionDirectoryNtDll::OpenExisting,
                    false
                ),
                Err(crate::error::NtStatusValue::ObjectNameNotFound.into())
            );
            assert_eq!(
                create(
                    f,
                    &path,
                    CreationDispositionDirectoryNtDll::CreateNew,
                    false
                ),
                Ok(IoStatus::Created)
            );
            assert_eq!(
                create(
                    f,
                    &path,
                    CreationDispositionDirectoryNtDll::OpenExisting,
                    true
                ),
                Ok(IoStatus::Opened)
            );

            // CreateNew
            assert_eq!(
                create(
                    f,
                    &path,
                    CreationDispositionDirectoryNtDll::CreateNew,
                    false
                ),
                Ok(IoStatus::Created)
            );
            assert_eq!(
                create(
                    f,
                    &path,
                    CreationDispositionDirectoryNtDll::CreateNew,
                    false
                ),
                Err(crate::error::NtStatusValue::ObjectNameCollision.into())
            );
            assert_eq!(
                create(
                    f,
                    &path,
                    CreationDispositionDirectoryNtDll::OpenExisting,
                    true
                ),
                Ok(IoStatus::Opened)
            );

            // OpenAlways
            assert_eq!(
                create(
                    f,
                    &path,
                    CreationDispositionDirectoryNtDll::OpenAlways,
                    false
                ),
                Ok(IoStatus::Created)
            );
            assert_eq!(
                create(
                    f,
                    &path,
                    CreationDispositionDirectoryNtDll::OpenAlways,
                    true
                ),
                Ok(IoStatus::Opened)
            );
        }
    }

    /*
    // TODO: Find a clever way to test this.
    #[test]
    fn directory_create_nt_creation_options() {
        crate::init_syscall_ids();

        panic!("not implemented, yet");
    }

    // TODO: Find a clever way to test this.
    #[test]
    fn directory_create_nt_extended_attributes() {
        crate::init_syscall_ids();

        panic!("not implemented, yet");
    }
    */

    #[test]
    fn directory_information_nt() {
        crate::init_syscall_ids();

        let path = String::from(r"\??\C:\Windows\");
        let path = StringW::from(path.as_ref());
        let attributes = crate::object::Attributes::from_name(&path);

        for f in &[
            (
                Directory::create_ntdll as NtCreateDirectory,
                Directory::information_ntdll as NtQueryBasicInformationDirectory
            ), (
                Directory::create_syscall as NtCreateDirectory,
                Directory::information_syscall as NtQueryBasicInformationDirectory
            )
        ] {
            let directory = f.0(
                DirectoryAccessModes::new().set(DirectoryAccessMode::ReadAttributes, true),
                &attributes,
                Attributes::new(),
                ShareModes::all(),
                CreationDispositionDirectoryNtDll::OpenExisting,
                CreationOptions::new(),
                None
            ).unwrap().0;

            assert_eq!(f.1(&directory).map(|_| ()), Ok(()));
        }
    }

    #[test]
    fn file_create_kernel32_path() {
        let paths = &[
            // Non-existent file.
            (
                "C:\\winapi2_this_must_not_exist.test\0",
                Err(crate::error::StatusValue::FileNotFound.into())
            ),
            // File in non-existent directory.
            (
                "C:\\winapi2_this_must_not_exist.test\\test.txt\0",
                Err(crate::error::StatusValue::PathNotFound.into())
            ),
            // Absolute directory.
            (
                "C:\\\0",
                Err(crate::error::StatusValue::BadFileType.into())
            ),
            // Absolute file.
            (
                "C:\\Windows\\System32\\ntdll.dll\0",
                Ok(None)
            ),
            // Relative directory.
            (
                "src\\\0",
                Err(crate::error::StatusValue::BadFileType.into())
            ),
            // Relative file.
            (
                "Cargo.toml\0",
                Ok(None)
            )
        ];

        for path in paths.iter() {
            let string = String::from(path.0);
            assert_eq!(File::create_kernel32(
                string.as_ref(),
                FileAccessModes::new(),
                ShareModes::all(),
                None,
                CreationDispositionFileKernel32::OpenExisting,
                Attributes::new(),
                None
            ).map(|r| r.1), path.1);
        }
    }

    /*
    // TODO: Implement use cases for file handles.
    #[test]
    fn file_create_kernel32_access_modes() {
        panic!("not implemented, yet");
    }

    // TODO: Find a clever way to test this.
    #[test]
    fn file_create_kernel32_share_modes() {
        panic!("not implemented, yet");
    }

    // TODO: Implement security descriptor logic.
    #[test]
    fn file_create_kernel32_security_descriptor() {
        panic!("not implemented, yet");
    }
    */

    #[test]
    fn file_create_kernel32_creation_disposition() {
        let path = String::from("winapi2_file_create_kernel32_creation_disposition\0");
        let path = path.as_ref();

        fn create(
            path: &Str,
            creation_disposition: CreationDispositionFileKernel32,
            delete_on_close: bool,
            generic_write: bool
        ) -> Result<(File, Option<crate::error::Status>), crate::error::Status> {
            File::create_kernel32(
                path,
                FileAccessModes::new()
                    .set_standard(crate::object::AccessMode::GenericWrite, generic_write),
                ShareModes::all(),
                None,
                creation_disposition,
                Attributes::new()
                    .set(Attribute::DeleteOnClose, delete_on_close),
                None
            )
        }

        // CreateNew
        assert_eq!(
            create(
                path,
                CreationDispositionFileKernel32::CreateNew,
                false,
                false
            ).map(|r| r.1),
            Ok(None)
        );
        assert_eq!(
            create(
                path,
                CreationDispositionFileKernel32::CreateNew,
                false,
                false
            ).map(|r| r.1),
            Err(crate::error::StatusValue::FileExists.into())
        );
        assert_eq!(
            create(
                path,
                CreationDispositionFileKernel32::OpenExisting,
                true,
                false
            ).map(|r| r.1),
            Ok(None)
        );

        // CreateAlways
        assert_eq!(
            create(
                path,
                CreationDispositionFileKernel32::CreateAlways,
                false,
                false
            ).map(|r| r.1),
            Ok(None)
        );
        assert_eq!(
            create(
                path,
                CreationDispositionFileKernel32::CreateAlways,
                true,
                false
            ).map(|r| r.1),
            Ok(Some(crate::error::StatusValue::AlreadyExists.into()))
        );

        // OpenExisting
        assert_eq!(
            create(
                path,
                CreationDispositionFileKernel32::OpenExisting,
                false,
                false
            ).map(|r| r.1),
            Err(crate::error::StatusValue::FileNotFound.into())
        );
        assert_eq!(
            create(
                path,
                CreationDispositionFileKernel32::CreateNew,
                false,
                false
            ).map(|r| r.1),
            Ok(None)
        );
        assert_eq!(
            create(
                path,
                CreationDispositionFileKernel32::OpenExisting,
                true,
                false
            ).map(|r| r.1),
            Ok(None)
        );

        // OpenAlways
        assert_eq!(
            create(
                path,
                CreationDispositionFileKernel32::OpenAlways,
                false,
                false
            ).map(|r| r.1),
            Ok(None)
        );
        assert_eq!(
            create(
                path,
                CreationDispositionFileKernel32::OpenAlways,
                true,
                false
            ).map(|r| r.1),
            Ok(Some(crate::error::StatusValue::AlreadyExists.into()))
        );

        // TruncateExisting
        assert_eq!(
            create(
                path,
                CreationDispositionFileKernel32::TruncateExisting,
                false,
                true
            ).map(|r| r.1),
            Err(crate::error::StatusValue::FileNotFound.into())
        );

        let file = create(
            path,
            CreationDispositionFileKernel32::CreateNew,
            false,
            true
        ).unwrap();
        assert_eq!(file.1, None);

        // Increase file size.
        assert_eq!(file.0.write_kernel32(&[1, 2, 3, 4], None), Ok(4));

        // Check the file size.
        assert_eq!(file.0.information_ntdll().unwrap().file_size, 4);

        assert_eq!(
            create(
                path,
                CreationDispositionFileKernel32::TruncateExisting,
                true,
                true
            ).map(|r| r.1),
            Ok(None)
        );

        // Check the truncated file size.
        assert_eq!(file.0.information_ntdll().unwrap().file_size, 0);
    }

    /*
    // TODO: Find a clever way to test this.
    #[test]
    fn file_create_kernel32_attributes() {
        panic!("not implemented, yet");
    }
    */

    #[test]
    fn file_create_kernel32_template() {
        fn create(
            path: &Str,
            creation_disposition: CreationDispositionFileKernel32,
            template: Option<&Object>,
            delete_on_close: bool
        ) -> File {
            File::create_kernel32(
                path,
                FileAccessModes::new(),
                ShareModes::all(),
                None,
                creation_disposition,
                Attributes::new()
                    .set(Attribute::DeleteOnClose, delete_on_close),
                template
            ).unwrap().0
        }

        let notepad = String::from("C:\\Windows\\notepad.exe\0");
        let notepad_handle = create(
            notepad.as_ref(), CreationDispositionFileKernel32::OpenExisting,
            None, false
        );
        let notepad_attributes = Object::attributes_kernel32(notepad.as_ref()).unwrap();

        let local = String::from("winapi2_file_create_kernel32_template\0");
        #[allow(unused)]
        let local_handle = create(
            local.as_ref(), CreationDispositionFileKernel32::CreateNew,
            Some(&Object::File(notepad_handle)), true
        );
        let local_attributes = Object::attributes_kernel32(local.as_ref()).unwrap();

        assert_eq!(notepad_attributes, local_attributes);
    }

    /*
    // TODO: Implement use cases for directory handles.
    #[test]
    fn file_create_nt_access_modes() {
        crate::init_syscall_ids();

        panic!("not implemented, yet");
    }
    */

    #[test]
    fn file_create_nt_object_attributes() {
        crate::init_syscall_ids();

        fn create(
            f: &NtCreateFile,
            attributes: &crate::object::Attributes
        ) -> Result<IoStatus, crate::error::NtStatus> {
            f(
                FileAccessModes::new()
                    .set(FileAccessMode::ReadAttributes, true),
                attributes,
                None,
                Attributes::new(),
                ShareModes::all(),
                CreationDispositionFileNtDll::OpenExisting,
                CreationOptions::new(),
                None
            ).map(|r| r.1)
        }

        for f in &[
            (File::create_ntdll as NtCreateFile, Directory::create_ntdll as NtCreateDirectory),
            (File::create_syscall as NtCreateFile, Directory::create_syscall as NtCreateDirectory)
        ] {
            let mut attributes = crate::object::Attributes::new(
                None,
                None,
                crate::object::AttributeFlags::new(),
                None,
                None
            );

            assert_eq!(create(&f.0, &attributes), Err(crate::error::NtStatusValue::ObjectPathSyntaxBad.into()));

            // object_name
            let notepad = String::from(r"\??\C:\Windows\notepad.exe");
            let notepad = StringW::from(notepad.as_ref());
            attributes.object_name = Some(&notepad);

            assert_eq!(create(&f.0, &attributes), Ok(IoStatus::Opened));

            // root_directory
            let windows = String::from(r"\??\C:\Windows\");
            let windows = StringW::from(windows.as_ref());
            let windows_attributes = crate::object::Attributes::from_name(&windows);
            let windows = f.1(
                DirectoryAccessModes::new().set(DirectoryAccessMode::List, true),
                &windows_attributes,
                Attributes::new(),
                ShareModes::all(),
                CreationDispositionDirectoryNtDll::OpenExisting,
                CreationOptions::new(),
                None,
            ).unwrap();
            attributes.root_directory = Some((windows.0).0.clone());
            let notepad_local = String::from("notepad.exe");
            let notepad_local = StringW::from(notepad_local.as_ref());
            attributes.object_name = Some(&notepad_local);

            assert_eq!(create(&f.0, &attributes), Ok(IoStatus::Opened));

            attributes.root_directory = None;

            // flags
            {
                // TODO: Check `Inherit` once process creation and handle enumeration is implemented.
                // TODO: Is `Permanent` usable in user mode?
                // TODO: Check `Exclusive` once process creation is implemented.

                // ForceCaseInsensitive
                let notepad_cased = String::from(r"\??\C:\WiNdOwS\NoTePaD.eXe");
                let notepad_cased = StringW::from(notepad_cased.as_ref());
                attributes.object_name = Some(&notepad_cased);

                // NTFS is case insensitive by default, so this assertion does not work.
                // assert_eq!(create(&attributes), Err(crate::error::NtStatusValue::ObjectNameNotFound.into()));

                attributes.flags = attributes.flags.set(
                    crate::object::AttributeFlag::ForceCaseInsensitive, true
                );
                assert_eq!(create(&f.0, &attributes), Ok(IoStatus::Opened));

                attributes.flags = attributes.flags.set(
                    crate::object::AttributeFlag::ForceCaseInsensitive, false
                );
                attributes.object_name = Some(&notepad);

                // TODO: Understand Microsoft's description and test `OpenIf`.
                // TODO: Check `OpenLink` once creating symbolic links is implemented.
                // TODO: Are `KernelHandle` and `ForceAccessCheck` testable in user mode?
                // TODO: Check `IgnoreImpersonatedDeviceMap` somehow.
            }

            // security_descriptor
            // TODO: Implement security descriptor logic.

            // security_quality_of_service
            // TODO: Implement security descriptor logic.
        }
    }

    #[test]
    fn file_create_nt_allocation_size() {
        crate::init_syscall_ids();

        for f in &[
            (
                Directory::create_ntdll as NtCreateDirectory,
                File::create_ntdll as NtCreateFile,
                File::information_ntdll as NtQueryBasicInformationFile,
                File::write_ntdll as NtWriteFile,
            ),
            (
                Directory::create_syscall as NtCreateDirectory,
                File::create_syscall as NtCreateFile,
                File::information_syscall as NtQueryBasicInformationFile,
                File::write_syscall as NtWriteFile,
            )
        ] {
            let dir = String::from(r"\??\C:\winapi2_file_create_nt_allocation_size\");
            let dir = StringW::from(dir.as_ref());
            let dir = crate::object::Attributes::from_name(&dir);
            #[allow(unused)]
            let dir = f.0(
                DirectoryAccessModes::new()
                    .set(DirectoryAccessMode::List, true)
                    .set_standard(crate::object::AccessMode::Delete, true),
                &dir,
                Attributes::new(),
                ShareModes::all(),
                CreationDispositionDirectoryNtDll::CreateNew,
                CreationOptions::new()
                    .set(CreationOption::DeleteOnClose, true),
                None
            ).unwrap().0;

            let path = String::from(r"\??\C:\winapi2_file_create_nt_allocation_size\winapi2_file_create_nt_allocation_size");
            let path = StringW::from(path.as_ref());
            let attributes = crate::object::Attributes::from_name(&path);

            let allocation_size = 1;

            let file = f.1(
                FileAccessModes::new()
                    .set(FileAccessMode::WriteData, true)
                    .set(FileAccessMode::ReadAttributes, true)
                    .set_standard(crate::object::AccessMode::Delete, true)
                    .set_standard(crate::object::AccessMode::Synchronize, true),
                &attributes,
                Some(&allocation_size),
                Attributes::new(),
                ShareModes::new(),
                CreationDispositionFileNtDll::CreateNew,
                CreationOptions::new()
                    .set(CreationOption::SynchronousIoNonAlert, true)
                    .set(CreationOption::DeleteOnClose, true),
                None
            ).unwrap().0;

            assert_eq!(f.2(&file).map(|r| (r.allocation_size, r.file_size)), Ok((0x1000, 0)));
            assert_eq!(f.3(&file, &[0; 0x800], None, None), Ok(0x800));
            assert_eq!(f.2(&file).map(|r| (r.allocation_size, r.file_size)), Ok((0x1000, 0x800)));
            assert_eq!(f.3(&file, &[0; 0x800], None, None), Ok(0x800));
            assert_eq!(f.2(&file).map(|r| (r.allocation_size, r.file_size)), Ok((0x1000, 0x1000)));
            assert_eq!(f.3(&file, &[0], None, None), Ok(1));
            assert_eq!(f.2(&file).map(|r| (r.allocation_size, r.file_size)), Ok((0x2000, 0x1001)));
        }
    }

    /*
    // TODO: Find a clever way to test this.
    #[test]
    fn file_create_nt_attributes() {
        crate::init_syscall_ids();

        panic!("not implemented, yet");
    }

    // TODO: Find a clever way to test this.
    #[test]
    fn file_create_nt_share_modes() {
        crate::init_syscall_ids();

        panic!("not implemented, yet");
    }
    */

    #[test]
    fn file_create_nt_creation_disposition() {
        crate::init_syscall_ids();

        for f in &[
            (Directory::create_ntdll as NtCreateDirectory, File::create_ntdll as NtCreateFile),
            (Directory::create_syscall as NtCreateDirectory, File::create_syscall as NtCreateFile)
        ] {
            let dir = String::from(r"\??\C:\winapi2_file_create_nt_creation_disposition\");
            let dir = StringW::from(dir.as_ref());
            let dir = crate::object::Attributes::from_name(&dir);
            #[allow(unused)]
            let dir = f.0(
                DirectoryAccessModes::new()
                    .set(DirectoryAccessMode::List, true)
                    .set_standard(crate::object::AccessMode::Delete, true),
                &dir,
                Attributes::new(),
                ShareModes::all(),
                CreationDispositionDirectoryNtDll::CreateNew,
                CreationOptions::new()
                    .set(CreationOption::DeleteOnClose, true),
                None
            ).unwrap().0;

            let path = String::from(r"\??\C:\winapi2_file_create_nt_creation_disposition\winapi2_file_create_nt_creation_disposition");
            let path = StringW::from(path.as_ref());

            fn create(
                f: &NtCreateFile,
                object_name: &StringW,
                creation_disposition: CreationDispositionFileNtDll,
                read_attributes: bool,
                write_data: bool,
                delete_on_close: bool,
                generic_write: bool
            ) -> Result<IoStatus, crate::error::NtStatus> {
                let attributes = crate::object::Attributes::from_name(object_name);
                f(
                    FileAccessModes::new()
                        .set(FileAccessMode::ReadAttributes, read_attributes)
                        .set(FileAccessMode::WriteData, write_data)
                        .set_standard(crate::object::AccessMode::Delete, delete_on_close)
                        .set_standard(crate::object::AccessMode::GenericWrite, generic_write),
                    &attributes,
                    None,
                    Attributes::new(),
                    ShareModes::all(),
                    creation_disposition,
                    CreationOptions::new()
                        .set(CreationOption::DeleteOnClose, delete_on_close),
                    None
                ).map(|r| r.1)
            }

            // CreateAlways
            assert_eq!(
                create(
                    &f.1,
                    &path,
                    CreationDispositionFileNtDll::CreateAlways,
                    false,
                    true,
                    false,
                    false
                ),
                Ok(IoStatus::Created)
            );
            assert_eq!(
                create(
                    &f.1,
                    &path,
                    CreationDispositionFileNtDll::CreateAlways,
                    false,
                    false,
                    true,
                    false
                ),
                Ok(IoStatus::Superseded)
            );

            // OpenExisting
            assert_eq!(
                create(
                    &f.1,
                    &path,
                    CreationDispositionFileNtDll::OpenExisting,
                    true,
                    false,
                    false,
                    false
                ),
                Err(crate::error::NtStatusValue::ObjectNameNotFound.into())
            );
            assert_eq!(
                create(
                    &f.1,
                    &path,
                    CreationDispositionFileNtDll::CreateNew,
                    false,
                    true,
                    false,
                    false
                ),
                Ok(IoStatus::Created)
            );
            assert_eq!(
                create(
                    &f.1,
                    &path,
                    CreationDispositionFileNtDll::OpenExisting,
                    false,
                    false,
                    true,
                    false
                ),
                Ok(IoStatus::Opened)
            );

            // CreateNew
            assert_eq!(
                create(
                    &f.1,
                    &path,
                    CreationDispositionFileNtDll::CreateNew,
                    false,
                    true,
                    false,
                    false
                ),
                Ok(IoStatus::Created)
            );
            assert_eq!(
                create(
                    &f.1,
                    &path,
                    CreationDispositionFileNtDll::CreateNew,
                    false,
                    true,
                    false,
                    false
                ),
                Err(crate::error::NtStatusValue::ObjectNameCollision.into())
            );
            assert_eq!(
                create(
                    &f.1,
                    &path,
                    CreationDispositionFileNtDll::OpenExisting,
                    false,
                    false,
                    true,
                    false
                ),
                Ok(IoStatus::Opened)
            );

            // OpenAlways
            assert_eq!(
                create(
                    &f.1,
                    &path,
                    CreationDispositionFileNtDll::OpenAlways,
                    false,
                    true,
                    false,
                    false
                ),
                Ok(IoStatus::Created)
            );
            assert_eq!(
                create(
                    &f.1,
                    &path,
                    CreationDispositionFileNtDll::OpenAlways,
                    false,
                    true,
                    true,
                    false
                ),
                Ok(IoStatus::Opened)
            );

            // TruncateExisting
            assert_eq!(
                create(
                    &f.1,
                    &path,
                    CreationDispositionFileNtDll::TruncateExisting,
                    false,
                    false,
                    false,
                    true
                ),
                Err(crate::error::NtStatusValue::ObjectNameNotFound.into())
            );
            assert_eq!(
                create(
                    &f.1,
                    &path,
                    CreationDispositionFileNtDll::CreateNew,
                    false,
                    true,
                    false,
                    false
                ),
                Ok(IoStatus::Created)
            );
            assert_eq!(
                create(
                    &f.1,
                    &path,
                    CreationDispositionFileNtDll::TruncateExisting,
                    false,
                    false,
                    true,
                    true
                ),
                Ok(IoStatus::Overwritten)
            );
            // TODO: Increase file size between the two calls and check it afterwards.

            // TruncateAlways
            assert_eq!(
                create(
                    &f.1,
                    &path,
                    CreationDispositionFileNtDll::TruncateAlways,
                    false,
                    true,
                    false,
                    false
                ),
                Ok(IoStatus::Created)
            );
            assert_eq!(
                create(
                    &f.1,
                    &path,
                    CreationDispositionFileNtDll::TruncateAlways,
                    false,
                    false,
                    true,
                    false
                ),
                Ok(IoStatus::Overwritten)
            );
            // TODO: Increase file size between the two calls and check it afterwards.
        }
    }

    /*
    // TODO: Find a clever way to test this.
    #[test]
    fn file_create_nt_creation_options() {
        crate::init_syscall_ids();

        panic!("not implemented, yet");
    }

    // TODO: Find a clever way to test this.
    #[test]
    fn file_create_nt_extended_attributes() {
        crate::init_syscall_ids();

        panic!("not implemented, yet");
    }
    */

    #[test]
    fn file_information_nt() {
        crate::init_syscall_ids();

        let path = String::from(r"\??\C:\Windows\System32\notepad.exe");
        let path = StringW::from(path.as_ref());
        let attributes = crate::object::Attributes::from_name(&path);

        for f in &[
            (
                File::create_ntdll as NtCreateFile,
                File::information_ntdll as NtQueryBasicInformationFile
            ), (
                File::create_syscall as NtCreateFile,
                File::information_syscall as NtQueryBasicInformationFile
            )
        ] {
            let file = f.0(
                FileAccessModes::new().set(FileAccessMode::ReadAttributes, true),
                &attributes,
                None,
                Attributes::new(),
                ShareModes::all(),
                CreationDispositionFileNtDll::OpenExisting,
                CreationOptions::new(),
                None
            ).unwrap().0;

            assert_eq!(f.1(&file).map(|_| ()), Ok(()));
        }
    }

    #[test]
    fn file_read_kernel32() {
        let notepad = String::from("C:\\Windows\\notepad.exe\0");

        let mut mz = unsafe {
            core::mem::MaybeUninit::<[core::mem::MaybeUninit<u8>; 2]>::uninit().assume_init()
        };

        // Without `ReadData` permission.
        let mut file = File::create_kernel32(
            notepad.as_ref(),
            FileAccessModes::new(),
            ShareModes::all(),
            None,
            CreationDispositionFileKernel32::OpenExisting,
            Attributes::new(),
            None
        ).unwrap().0;

        assert_eq!(
            file.read_kernel32(&mut mz, None),
            Err(crate::error::StatusValue::AccessDenied.into())
        );

        // With `ReadData` permission.
        file = File::create_kernel32(
            notepad.as_ref(),
            FileAccessModes::new().set(FileAccessMode::ReadData, true),
            ShareModes::all(),
            None,
            CreationDispositionFileKernel32::OpenExisting,
            Attributes::new(),
            None
        ).unwrap().0;

        // Check the DOS header signature.
        assert_eq!(
            file.read_kernel32(&mut mz, None),
            Ok([b'M', b'Z'].as_mut())
        );

        // Read the offset to the PE header from the DOS header.
        let mut offset_pe_header = unsafe {
            core::mem::MaybeUninit::<[core::mem::MaybeUninit<u8>; 4]>::uninit().assume_init()
        };
        let offset_pe_header: &u32 = unsafe { crate::conversion::cast_mut(file.read_kernel32(
            &mut offset_pe_header,
            Some(&mut crate::io::Overlapped::new(0x3C, None))
        ).unwrap()).unwrap() };

        // Read and check the PE header signature.
        let mut pe_header_signature = unsafe {
            core::mem::MaybeUninit::<[core::mem::MaybeUninit<u8>; 4]>::uninit().assume_init()
        };
        assert_eq!(
            file.read_kernel32(
                &mut pe_header_signature,
                Some(&mut crate::io::Overlapped::new(*offset_pe_header as u64, None))
            ),
            // f.1(&file, None, &mut pe_header_signature, Some(&(*offset_pe_header as u64))),
            Ok([b'P', b'E', 0, 0].as_mut())
        );

        // TODO: Use asynchronous file handle + `Overlap.event`.
    }

    #[test]
    fn file_read_nt() {
        crate::init_syscall_ids();

        for f in &[
            (
                File::create_ntdll as NtCreateFile,
                File::read_ntdll as NtReadFile
            ),
            (
                File::create_syscall as NtCreateFile,
                File::read_syscall as NtReadFile
            )
        ] {
            let notepad = String::from(r"\??\C:\Windows\notepad.exe");
            let notepad = StringW::from(notepad.as_ref());
            let notepad = crate::object::Attributes::from_name(&notepad);

            let mut mz = unsafe {
                core::mem::MaybeUninit::<[core::mem::MaybeUninit<u8>; 2]>::uninit().assume_init()
            };

            // Without `ReadData` permission.
            let mut file = f.0(
                FileAccessModes::new()
                    .set_standard(crate::object::AccessMode::Synchronize, true),
                &notepad,
                None,
                Attributes::new(),
                ShareModes::all(),
                CreationDispositionFileNtDll::OpenExisting,
                CreationOptions::new().set(CreationOption::SynchronousIoNonAlert, true),
                None
            ).unwrap().0;

            assert_eq!(
                f.1(&file, &mut mz, None, None),
                Err(crate::error::NtStatusValue::AccessDenied.into())
            );

            // With `ReadData` permission.
            file = f.0(
                FileAccessModes::new()
                    .set(FileAccessMode::ReadData, true)
                    .set_standard(crate::object::AccessMode::Synchronize, true),
                &notepad,
                None,
                Attributes::new(),
                ShareModes::all(),
                CreationDispositionFileNtDll::OpenExisting,
                CreationOptions::new().set(CreationOption::SynchronousIoNonAlert, true),
                None
            ).unwrap().0;

            // Check the DOS header signature.
            assert_eq!(
                f.1(&file, &mut mz, None, None),
                Ok([b'M', b'Z'].as_mut())
            );

            // Read the offset to the PE header from the DOS header.
            let mut offset_pe_header = unsafe {
                core::mem::MaybeUninit::<[core::mem::MaybeUninit<u8>; 4]>::uninit().assume_init()
            };
            let offset_pe_header: &u32 = unsafe { crate::conversion::cast_mut(
                f.1(&file, &mut offset_pe_header, Some(&0x3C), None).unwrap()
            ).unwrap() };

            // Read and check the PE header signature.
            let mut pe_header_signature = unsafe {
                core::mem::MaybeUninit::<[core::mem::MaybeUninit<u8>; 4]>::uninit().assume_init()
            };
            assert_eq!(
                f.1(&file, &mut pe_header_signature, Some(&(*offset_pe_header as u64)), None),
                Ok([b'P', b'E', 0, 0].as_mut())
            );

            // TODO: Use asynchronous file handle + the `event` argument.
        }
    }

    #[test]
    fn file_write_kernel32() {
        let path = String::from("winapi2_file_write_kernel32\0");
        let path = path.as_ref();

        let file = File::create_kernel32(
            path,
            FileAccessModes::new()
                .set(FileAccessMode::ReadData, true)
                .set(FileAccessMode::WriteData, true)
                .set_standard(crate::object::AccessMode::Delete, true),
            ShareModes::new(),
            None,
            CreationDispositionFileKernel32::CreateNew,
            Attributes::new().set(Attribute::DeleteOnClose, true),
            None
        ).unwrap().0;

        let mut buffer = unsafe {
            core::mem::MaybeUninit::<[core::mem::MaybeUninit<u8>; 10]>::uninit().assume_init()
        };

        assert_eq!(Object::information_kernel32(path).unwrap().file_size(), 0);
        assert_eq!(file.read_kernel32(&mut buffer, None), Ok([].as_mut()));

        assert_eq!(file.write_kernel32(&[0, 1, 2], None), Ok(3));
        assert_eq!(Object::information_kernel32(path).unwrap().file_size(), 3);
        assert_eq!(file.read_kernel32(&mut buffer, None), Ok([].as_mut()));
        assert_eq!(
            file.read_kernel32(&mut buffer, Some(
                &mut crate::io::Overlapped::new(0, None))
            ), Ok([0, 1, 2].as_mut())
        );
        assert_eq!(
            file.read_kernel32(&mut buffer, Some(
                &mut crate::io::Overlapped::new(2, None))
            ), Ok([2].as_mut())
        );

        assert_eq!(file.write_kernel32(&[3, 4, 5], None), Ok(3));
        assert_eq!(Object::information_kernel32(path).unwrap().file_size(), 6);
        assert_eq!(
            file.read_kernel32(&mut buffer, Some(
                &mut crate::io::Overlapped::new(3, None))
            ), Ok([3, 4, 5].as_mut())
        );
        assert_eq!(
            file.read_kernel32(&mut buffer, Some(
                &mut crate::io::Overlapped::new(0, None))
            ), Ok([0, 1, 2, 3, 4, 5].as_mut())
        );

        assert_eq!(file.write_kernel32(&[6, 7, 8], None), Ok(3));
        assert_eq!(Object::information_kernel32(path).unwrap().file_size(), 9);
        assert_eq!(
            file.read_kernel32(&mut buffer, Some(
                &mut crate::io::Overlapped::new(0, None))
            ), Ok([0, 1, 2, 3, 4, 5, 6, 7, 8].as_mut())
        );

        assert_eq!(file.write_kernel32(&[9, 10, 11], Some(
            &mut crate::io::Overlapped::new(1, None))
        ), Ok(3));
        assert_eq!(Object::information_kernel32(path).unwrap().file_size(), 9);
        assert_eq!(
            file.read_kernel32(&mut buffer, Some(
                &mut crate::io::Overlapped::new(0, None))
            ), Ok([0, 9, 10, 11, 4, 5, 6, 7, 8].as_mut())
        );
        assert_eq!(
            file.read_kernel32(&mut buffer[..5], Some(
                &mut crate::io::Overlapped::new(1, None))
            ), Ok([9, 10, 11, 4, 5].as_mut())
        );

        assert_eq!(file.write_kernel32(&[0; 0x800], None), Ok(0x800));
        assert_eq!(Object::information_kernel32(path).unwrap().file_size(), 0x806);

        // TODO: Use asynchronous file handle + `Overlap.event`.
    }

    #[test]
    fn file_write_nt() {
        crate::init_syscall_ids();

        for f in &[
            (
                Directory::create_ntdll as NtCreateDirectory,
                File::create_ntdll as NtCreateFile,
                File::information_ntdll as NtQueryBasicInformationFile,
                File::read_ntdll as NtReadFile,
                File::write_ntdll as NtWriteFile
            ),
            (
                Directory::create_syscall as NtCreateDirectory,
                File::create_syscall as NtCreateFile,
                File::information_syscall as NtQueryBasicInformationFile,
                File::read_syscall as NtReadFile,
                File::write_syscall as NtWriteFile
            )
        ] {
            let dir = String::from(r"\??\C:\winapi2_file_write_nt\");
            let dir = StringW::from(dir.as_ref());
            let dir = crate::object::Attributes::from_name(&dir);
            #[allow(unused)]
            let dir = f.0(
                DirectoryAccessModes::new()
                    .set(DirectoryAccessMode::List, true)
                    .set_standard(crate::object::AccessMode::Delete, true),
                &dir,
                Attributes::new(),
                ShareModes::all(),
                CreationDispositionDirectoryNtDll::CreateNew,
                CreationOptions::new()
                    .set(CreationOption::DeleteOnClose, true),
                None
            ).unwrap().0;

            let path = String::from(r"\??\C:\winapi2_file_write_nt\winapi2_file_write_nt");
            let path = StringW::from(path.as_ref());
            let attributes = crate::object::Attributes::from_name(&path);

            let file = f.1(
                FileAccessModes::new()
                    .set(FileAccessMode::ReadAttributes, true)
                    .set(FileAccessMode::ReadData, true)
                    .set(FileAccessMode::WriteData, true)
                    .set_standard(crate::object::AccessMode::Delete, true)
                    .set_standard(crate::object::AccessMode::Synchronize, true),
                &attributes,
                Some(&0x806),
                Attributes::new(),
                ShareModes::new(),
                CreationDispositionFileNtDll::CreateNew,
                CreationOptions::new()
                    .set(CreationOption::SynchronousIoNonAlert, true)
                    .set(CreationOption::DeleteOnClose, true),
                None
            ).unwrap().0;

            let mut buffer = unsafe {
                core::mem::MaybeUninit::<[core::mem::MaybeUninit<u8>; 10]>::uninit().assume_init()
            };

            assert_eq!(f.2(&file).unwrap().file_size, 0);
            assert_eq!(
                f.3(&file, &mut buffer, None, None),
                Err(crate::error::NtStatusValue::EndOfFile.into())
            );

            assert_eq!(f.4(&file, &[0, 1, 2], None, None), Ok(3));
            assert_eq!(f.2(&file).unwrap().file_size, 3);
            assert_eq!(
                f.3(&file, &mut buffer, None, None),
                Err(crate::error::NtStatusValue::EndOfFile.into())
            );
            assert_eq!(f.3(&file, &mut buffer, Some(&0), None), Ok([0, 1, 2].as_mut()));
            assert_eq!(f.3(&file, &mut buffer, Some(&2), None), Ok([2].as_mut()));

            assert_eq!(f.4(&file, &[3, 4, 5], None, None), Ok(3));
            assert_eq!(f.2(&file).unwrap().file_size, 6);
            assert_eq!(f.3(&file, &mut buffer, Some(&3), None), Ok([3, 4, 5].as_mut()));
            assert_eq!(f.3(&file, &mut buffer, Some(&0), None), Ok([0, 1, 2, 3, 4, 5].as_mut()));

            assert_eq!(f.4(&file, &[6, 7, 8], None, None), Ok(3));
            assert_eq!(f.2(&file).unwrap().file_size, 9);
            assert_eq!(f.3(&file, &mut buffer, Some(&0), None), Ok([0, 1, 2, 3, 4, 5, 6, 7, 8].as_mut()));

            assert_eq!(f.4(&file, &[9, 10, 11], Some(&1), None), Ok(3));
            assert_eq!(f.2(&file).unwrap().file_size, 9);
            assert_eq!(f.3(&file, &mut buffer, Some(&0), None), Ok([0, 9, 10, 11, 4, 5, 6, 7, 8].as_mut()));
            assert_eq!(f.3(&file, &mut buffer[..5], Some(&1), None), Ok([9, 10, 11, 4, 5].as_mut()));

            assert_eq!(f.4(&file, &[0; 0x800], None, None), Ok(0x800));
            assert_eq!(f.2(&file).unwrap().file_size, 0x806);

            // TODO: Use asynchronous file handle + the `event` argument.
        }
    }

    #[test]
    fn object_attributes_kernel32() {
        // Non-existent file.
        let path = String::from("C:\\winapi2_this_must_not_exist.test\0");
        assert_eq!(
            Object::attributes_kernel32(path.as_ref()).map(|_| ()),
            Err(crate::error::StatusValue::FileNotFound.into())
        );

        // File in non-existent directory.
        let path = String::from("C:\\winapi2_this_must_not_exist.test\\test.txt\0");
        assert_eq!(
            Object::attributes_kernel32(path.as_ref()).map(|_| ()),
            Err(crate::error::StatusValue::PathNotFound.into())
        );

        // Absolute directory.
        let path = String::from("C:\\\0");
        let attributes = Object::attributes_kernel32(path.as_ref()).unwrap();

        assert!(!attributes.has(Attribute::ReadOnly));
        assert!(attributes.has(Attribute::Directory));

        // Absolute file.
        let path = String::from("C:\\Windows\\System32\\ntdll.dll\0");
        let attributes = Object::attributes_kernel32(path.as_ref()).unwrap();

        assert!(!attributes.has(Attribute::ReadOnly));
        assert!(!attributes.has(Attribute::Directory));

        // Relative directory.
        let path = String::from("src\\\0");
        let attributes = Object::attributes_kernel32(path.as_ref()).unwrap();

        assert!(!attributes.has(Attribute::ReadOnly));
        assert!(attributes.has(Attribute::Directory));

        // Relative file.
        let path = String::from("Cargo.toml\0");
        let attributes = Object::attributes_kernel32(path.as_ref()).unwrap();

        assert!(!attributes.has(Attribute::ReadOnly));
        assert!(!attributes.has(Attribute::Directory));
    }

    #[test]
    fn object_attributes_nt() {
        crate::init_syscall_ids();

        for f in &[
            Object::attributes_ntdll as NtQueryObjectAttributes,
            Object::attributes_syscall as NtQueryObjectAttributes,
        ] {
            // Non-existent file.
            let path = String::from(r"\??\C:\winapi2_this_must_not_exist.test");
            let path = StringW::from(path.as_ref());
            let object_attributes = crate::object::Attributes::from_name(&path);
            assert_eq!(
                f(&object_attributes).map(|_| ()),
                Err(crate::error::NtStatusValue::ObjectNameNotFound.into())
            );

            // File in non-existent directory.
            let path = String::from(r"\??\C:\winapi2_this_must_not_exist.test\test.txt");
            let path = StringW::from(path.as_ref());
            let object_attributes = crate::object::Attributes::from_name(&path);
            assert_eq!(
                f(&object_attributes).map(|_| ()),
                Err(crate::error::NtStatusValue::ObjectPathNotFound.into())
            );

            // Directory.
            let path = String::from(r"\??\C:\");
            let path = StringW::from(path.as_ref());
            let object_attributes = crate::object::Attributes::from_name(&path);
            let attributes = f(&object_attributes).unwrap();

            assert!(!attributes.has(Attribute::ReadOnly));
            assert!(attributes.has(Attribute::Directory));

            // File.
            let path = String::from(r"\??\C:\Windows\System32\ntdll.dll");
            let path = StringW::from(path.as_ref());
            let object_attributes = crate::object::Attributes::from_name(&path);
            let attributes = f(&object_attributes).unwrap();

            assert!(!attributes.has(Attribute::ReadOnly));
            assert!(!attributes.has(Attribute::Directory));
        }
    }

    #[test]
    fn object_information_kernel32() {
        // Non-existent file.
        let path = String::from("C:\\winapi2_this_must_not_exist.test\0");
        assert_eq!(
            Object::information_kernel32(path.as_ref()).map(|_| ()),
            Err(crate::error::StatusValue::FileNotFound.into())
        );

        // File in non-existent directory.
        let path = String::from("C:\\winapi2_this_must_not_exist.test\\test.txt\0");
        assert_eq!(
            Object::information_kernel32(path.as_ref()).map(|_| ()),
            Err(crate::error::StatusValue::PathNotFound.into())
        );

        // Absolute directory.
        let path = String::from("C:\\\0");
        let info = Object::information_kernel32(path.as_ref()).unwrap();

        assert!(!info.attributes.has(Attribute::ReadOnly));
        assert!(info.attributes.has(Attribute::Directory));

        // Absolute file.
        let path = String::from("C:\\Windows\\System32\\ntdll.dll\0");
        let info = Object::information_kernel32(path.as_ref()).unwrap();

        assert!(!info.attributes.has(Attribute::ReadOnly));
        assert!(!info.attributes.has(Attribute::Directory));

        // Relative directory.
        let path = String::from("src\\\0");
        let info = Object::information_kernel32(path.as_ref()).unwrap();

        assert!(!info.attributes.has(Attribute::ReadOnly));
        assert!(info.attributes.has(Attribute::Directory));

        // Relative file.
        let path = String::from("Cargo.toml\0");
        let info = Object::information_kernel32(path.as_ref()).unwrap();

        assert!(!info.attributes.has(Attribute::ReadOnly));
        assert!(!info.attributes.has(Attribute::Directory));
    }

    #[test]
    fn object_information_nt() {
        crate::init_syscall_ids();

        for f in &[
            Object::information_ntdll as NtQueryObjectInformation,
            Object::information_syscall as NtQueryObjectInformation,
        ] {
            // Non-existent file.
            let path = String::from(r"\??\C:\winapi2_this_must_not_exist.test");
            let path = StringW::from(path.as_ref());
            let object_attributes = crate::object::Attributes::from_name(&path);
            assert_eq!(
                f(&object_attributes).map(|_| ()),
                Err(crate::error::NtStatusValue::ObjectNameNotFound.into())
            );

            // File in non-existent directory.
            let path = String::from(r"\??\C:\winapi2_this_must_not_exist.test\test.txt");
            let path = StringW::from(path.as_ref());
            let object_attributes = crate::object::Attributes::from_name(&path);
            assert_eq!(
                f(&object_attributes).map(|_| ()),
                Err(crate::error::NtStatusValue::ObjectPathNotFound.into())
            );

            // Directory.
            let path = String::from(r"\??\C:\");
            let path = StringW::from(path.as_ref());
            let object_attributes = crate::object::Attributes::from_name(&path);
            let info = f(&object_attributes).unwrap();

            assert!(!info.attributes.has(Attribute::ReadOnly));
            assert!(info.attributes.has(Attribute::Directory));

            // File.
            let path = String::from(r"\??\C:\Windows\System32\ntdll.dll");
            let path = StringW::from(path.as_ref());
            let object_attributes = crate::object::Attributes::from_name(&path);
            let info = f(&object_attributes).unwrap();

            assert!(!info.attributes.has(Attribute::ReadOnly));
            assert!(!info.attributes.has(Attribute::Directory));
        }
    }
}