//! Direct implementation for the exports by several Windows dynamically loaded libraries.

/// Table that stores all system call ids which might get used by the internal functions.
#[allow(missing_docs)]
pub struct Ids {
    pub close: u16,
    pub create_file: u16,
    pub open_process: u16,
    pub query_full_attributes_file: u16,
    pub query_information_process: u16,
    pub query_system_information: u16,
    pub terminate_process: u16
}

/// Global instance of system call ids that is used by all internal functions.
pub static mut IDS: Option<Ids> = None;

impl Ids {
    /// Initializes the system call id table with the `Windows 10 v1909` values.
    pub fn initialize_10_1909() {
        #[cfg(target_arch = "x86")]
        unsafe {
            // Windows 10 Professional x86 v1909.
            IDS = Some(Ids {
                close: 0x18D,
                create_file: 0x178,
                open_process: 0xE9,
                query_full_attributes_file: 0xC0,
                query_information_process: 0xB9,
                query_system_information: 0x9D,
                terminate_process: 0x24
            });
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            // Windows 10 Professional x86_64 v1909.
            IDS = Some(Ids {
                close: 0x0F,
                create_file: 0x55,
                open_process: 0x26,
                query_full_attributes_file: 0x140,
                query_information_process: 0x19,
                query_system_information: 0x36,
                terminate_process: 0x2C
            });
        }
    }

    /// Initializes the system call id table with the `Windows 10 v2004` values.
    pub fn initialize_10_2004() {
        #[cfg(target_arch = "x86")]
        unsafe {
            // Windows 10 Professional x86 v2004.
            IDS = Some(Ids {
                close: 0x18E,
                create_file: 0x178,
                open_process: 0xE9,
                query_full_attributes_file: 0xC0,
                query_information_process: 0xB9,
                query_system_information: 0x9D,
                terminate_process: 0x24
            });
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            // Windows 10 Professional x86_64 v2004.
            IDS = Some(Ids {
                close: 0x0F,
                create_file: 0x55,
                open_process: 0x26,
                query_full_attributes_file: 0x146,
                query_information_process: 0x19,
                query_system_information: 0x36,
                terminate_process: 0x2C
            });
        }
    }
}

// TODO: Add x86 assembly shell code variant.
// TODO: Handle more than 11 parameters (if necessary).
// TODO: Handle WoW64?
#[cfg(target_arch = "x86_64")]
macro_rules! syscall {
    ($id:ident) => {
        syscall!(#1 $id)
    };
    ($id:ident, $p1:ident) => {
        syscall!(#1 $id, "{rcx}"($p1))
    };
    ($id:ident, $p1:ident, $p2:ident) => {
        syscall!(#1 $id, "{rcx}"($p1), "{rdx}"($p2))
    };
    ($id:ident, $p1:ident, $p2:ident, $p3:ident) => {
        syscall!(#1 $id, "{rcx}"($p1), "{rdx}"($p2), "{r8}"($p3))
    };
    ($id:ident, $p1:ident, $p2:ident, $p3:ident, $p4:ident) => {
        syscall!(#1 $id, "{rcx}"($p1), "{rdx}"($p2), "{r8}"($p3), "{r9}"($p4))
    };
    (#1 $id:ident, $($input:tt)*) => {
        syscall!(#2 $id, "
            sub rsp, 0x20
            mov r10, rcx
            syscall
            add rsp, 0x20
        ", $($input)*)
    };
    ($id:ident, $p1:ident, $p2:ident, $p3:ident, $p4:ident, $p5:ident) => {
        syscall!(#2 $id, "
            sub rsp, 0x30
            mov [rsp + 0x28], $6
            mov r10, rcx
            syscall
            add rsp, 0x30
        ", "{rcx}"($p1), "{rdx}"($p2), "{r8}"($p3), "{r9}"($p4), "rn"($p5))
    };
    ($id:ident, $p1:ident, $p2:ident, $p3:ident, $p4:ident, $p5:ident, $p6:ident) => {
        syscall!(#2 $id, "
            sub rsp, 0x40
            mov [rsp + 0x28], $6
            mov [rsp + 0x30], $7
            mov r10, rcx
            syscall
            add rsp, 0x40
        ", "{rcx}"($p1), "{rdx}"($p2), "{r8}"($p3), "{r9}"($p4), "rn"($p5), "rn"($p6))
    };
    ($id:ident, $p1:ident, $p2:ident, $p3:ident, $p4:ident, $p5:ident, $p6:ident, $p7:ident) => {
        syscall!(#2 $id, "
            sub rsp, 0x40
            mov [rsp + 0x28], $6
            mov [rsp + 0x30], $7
            mov [rsp + 0x38], $8
            mov r10, rcx
            syscall
            add rsp, 0x40
        ", "{rcx}"($p1), "{rdx}"($p2), "{r8}"($p3), "{r9}"($p4), "rn"($p5), "rn"($p6), "rn"($p7))
    };
    ($id:ident, $p1:ident, $p2:ident, $p3:ident, $p4:ident, $p5:ident, $p6:ident, $p7:ident,
     $p8:ident)
    => {
        syscall!(#2 $id, "
            sub rsp, 0x50
            mov [rsp + 0x28], $6
            mov [rsp + 0x30], $7
            mov [rsp + 0x38], $8
            mov [rsp + 0x40], $9
            mov r10, rcx
            syscall
            add rsp, 0x50
        ", "{rcx}"($p1), "{rdx}"($p2), "{r8}"($p3), "{r9}"($p4), "rn"($p5), "rn"($p6), "rn"($p7),
        "rn"($p8))
    };
    ($id:ident, $p1:ident, $p2:ident, $p3:ident, $p4:ident, $p5:ident, $p6:ident, $p7:ident,
     $p8:ident, $p9:ident)
    => {
        syscall!(#2 $id, "
            sub rsp, 0x50
            mov [rsp + 0x28], $6
            mov [rsp + 0x30], $7
            mov [rsp + 0x38], $8
            mov [rsp + 0x40], $9
            mov [rsp + 0x48], $10
            mov r10, rcx
            syscall
            add rsp, 0x50
        ", "{rcx}"($p1), "{rdx}"($p2), "{r8}"($p3), "{r9}"($p4), "rn"($p5), "rn"($p6), "rn"($p7),
        "rn"($p8), "rn"($p9))
    };
    ($id:ident, $p1:ident, $p2:ident, $p3:ident, $p4:ident, $p5:ident, $p6:ident, $p7:ident,
     $p8:ident, $p9:ident, $p10:ident)
    => {
        syscall!(#2 $id, "
            sub rsp, 0x60
            mov [rsp + 0x28], $6
            mov [rsp + 0x30], $7
            mov [rsp + 0x38], $8
            mov [rsp + 0x40], $9
            mov [rsp + 0x48], $10
            mov [rsp + 0x50], $11
            mov r10, rcx
            syscall
            add rsp, 0x60
        ", "{rcx}"($p1), "{rdx}"($p2), "{r8}"($p3), "{r9}"($p4), "rn"($p5), "rn"($p6), "rn"($p7),
        "rn"($p8), "rn"($p9), "rn"($p10))
    };
    ($id:ident, $p1:ident, $p2:ident, $p3:ident, $p4:ident, $p5:ident, $p6:ident, $p7:ident,
     $p8:ident, $p9:ident, $p10:ident, $p11:ident)
    => {
        syscall!(#2 $id, "
            sub rsp, 0x60
            mov [rsp + 0x28], $6
            mov [rsp + 0x30], $7
            mov [rsp + 0x38], $8
            mov [rsp + 0x40], $9
            mov [rsp + 0x48], $10
            mov [rsp + 0x50], $11
            mov [rsp + 0x58], $12
            mov r10, rcx
            syscall
            add rsp, 0x60
        ", "{rcx}"($p1), "{rdx}"($p2), "{r8}"($p3), "{r9}"($p4), "rn"($p5), "rn"($p6), "rn"($p7),
        "rn"($p8), "rn"($p9), "rn"($p10), "rn"($p11))
    };
    (#2 $id:ident, $command:expr, $($input:tt)*) => {{
        let index = match IDS {
            Some(ref ids) => ids.$id,
            None => return Some(crate::error::NtStatusValue::InvalidSystemService.into())
        } as usize;

        let result: u32;
        // TODO: Upgrade to new `asm!` macro, see https://github.com/rust-lang/rfcs/pull/2873
        llvm_asm!(
            $command :
            "={eax}"(result) :
            "{eax}"(index), $($input)* :
            "r10" :
            "intel", "volatile"
        );

        *(&result as *const _ as *const crate::error::NtStatusResult)
    }};
}

/// Official documentation: [ntdll.NtClose](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntclose).
#[allow(non_snake_case)]
#[cfg(winapi = "syscall")]
#[inline(always)]
pub(crate) unsafe fn NtClose(
    object: crate::object::Handle
) -> crate::error::NtStatusResult {
    let object = *(&object as *const _ as *const isize);

    syscall!(close, object)
}

/// Official documentation: [ntdll.NtCreateFile](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile).
#[allow(non_snake_case)]
#[inline(always)]
pub(crate) unsafe fn NtCreateFile(
    handle: *mut crate::object::Handle,
    // Specializations:
    // - `crate::file::DirectoryAccessModes`
    // - `crate::file::FileAccessModes`
    access_modes: u32,
    object_attributes: &crate::object::Attributes,
    io_status_block: *mut crate::file::IoStatusBlock,
    allocation_size: Option<&u64>,
    attributes: crate::file::Attributes,
    share_modes: crate::file::ShareModes,
    // Specializations:
    // - `crate::file::CreationDispositionDirectoryNtDll`
    // - `crate::file::CreationDispositionFileNtDll`
    creation_disposition: u32,
    creation_options: crate::file::CreationOptions,
    extended_attributes: Option<&crate::file::ntfs::ExtendedAttributesInformation>,
    extended_attributes_size: u32
) -> crate::error::NtStatusResult {
    let attributes = *(&attributes as *const _ as *const u32) as usize;
    let share_modes = *(&share_modes as *const _ as *const u32) as usize;
    let creation_options = *(&creation_options as *const _ as *const u32) as usize;

    syscall!(create_file,
        handle, access_modes, object_attributes, io_status_block, allocation_size, attributes,
        share_modes, creation_disposition, creation_options, extended_attributes,
        extended_attributes_size
    )
}

/// Official documentation: [ntdll.NtOpenProcess](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess).
#[allow(non_snake_case)]
#[inline(always)]
pub(crate) unsafe fn NtOpenProcess(
    handle: *mut crate::object::Handle,
    access_modes: crate::process::AccessModes,
    attributes: &crate::object::Attributes,
    client_id: &crate::process::ClientId
) -> crate::error::NtStatusResult {
    let access_modes = *(&access_modes as *const _ as *const u32) as usize;

    syscall!(open_process, handle, access_modes, attributes, client_id)
}

/// Official documentation: [ntdll.NtQueryFullAttributesFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwqueryfullattributesfile).
#[allow(non_snake_case)]
#[inline(always)]
pub(crate) unsafe fn NtQueryFullAttributesFile(
    attributes: &crate::object::Attributes,
    information: *mut crate::file::info::BasicNtDll
) -> crate::error::NtStatusResult {
    syscall!(query_full_attributes_file, attributes, information)
}

/// Official documentation: [ntdll.NtQueryInformationProcess](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess).
#[allow(non_snake_case)]
#[inline(always)]
pub(crate) unsafe fn NtQueryInformationProcess(
    process: crate::object::Handle,
    information: crate::process::Information,
    buffer: *mut u8,
    buffer_size: u32,
    written_size: *mut u32
) -> crate::error::NtStatusResult {
    syscall!(query_information_process, process, information, buffer, buffer_size, written_size)
}

/// Official documentation: [ntdll.NtQuerySystemInformation](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation).
#[allow(non_snake_case)]
#[inline(always)]
pub(crate) unsafe fn NtQuerySystemInformation(
    information: crate::system::Information,
    buffer: *const u8,
    buffer_size: u32,
    return_size: Option<&u32>
) -> Option<crate::error::NtStatus> {
    syscall!(query_system_information, information, buffer, buffer_size, return_size)
}

/// Official documentation: [ntdll.NtTerminateProcess](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-zwterminateprocess).
#[allow(non_snake_case)]
#[inline(always)]
pub(crate) unsafe fn NtTerminateProcess(
    process: crate::object::Handle,
    exit_code: u32
) -> crate::error::NtStatusResult {
    let process = *(&process as *const _ as *const isize);

    syscall!(terminate_process, process, exit_code)
}