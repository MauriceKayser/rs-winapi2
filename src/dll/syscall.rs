//! Direct implementation for the exports by several Windows dynamically loaded libraries.

/// Table that stores all system call ids which might get used by the internal functions.
#[allow(missing_docs)]
pub struct Ids {
    pub close: u16,
    pub create_file: u16,
    pub open_process: u16,
    pub query_full_attributes_file: u16,
    pub query_information_file: u16,
    pub query_information_process: u16,
    pub query_system_information: u16,
    pub read_file: u16,
    pub terminate_process: u16,
    pub write_file: u16
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
                query_information_file: 0xBC,
                query_information_process: 0xB9,
                query_system_information: 0x9D,
                read_file: 0x08E,
                terminate_process: 0x24,
                write_file: 0x07
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
                query_information_file: 0x11,
                query_information_process: 0x19,
                query_system_information: 0x36,
                read_file: 0x06,
                terminate_process: 0x2C,
                write_file: 0x08
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
                query_information_file: 0xBC,
                query_information_process: 0xB9,
                query_system_information: 0x9D,
                read_file: 0x8E,
                terminate_process: 0x24,
                write_file: 0x07
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
                query_information_file: 0x11,
                query_information_process: 0x19,
                query_system_information: 0x36,
                read_file: 0x06,
                terminate_process: 0x2C,
                write_file: 0x08
            });
        }
    }
}

// TODO: Add x86 assembly shell code variant and optionally handle WoW64?
#[cfg(target_arch = "x86_64")]
macro_rules! syscall {
    ($id:ident) => { syscall!(#1 $id) };
    ($id:ident, $p1:ident) => { syscall!(#1 $id,
        inout("rcx") $p1 => _,
        out("rdx") _,
        out("r8") _,
        out("r9") _
    ) };
    ($id:ident, $p1:ident, $p2:ident) => { syscall!(#1 $id,
        inout("rcx") $p1 => _,
        inout("rdx") $p2 => _,
        out("r8") _,
        out("r9") _
    ) };
    ($id:ident, $p1:ident, $p2:ident, $p3:ident) => { syscall!(#1 $id,
        inout("rcx") $p1 => _,
        inout("rdx") $p2 => _,
        inout("r8") $p3 => _,
        out("r9") _
    ) };
    ($id:ident, $p1:ident, $p2:ident, $p3:ident, $p4:ident) => { syscall!(#1 $id,
        inout("rcx") $p1 => _,
        inout("rdx") $p2 => _,
        inout("r8") $p3 => _,
        inout("r9") $p4 => _
    ) };
    // More than 4 arguments have to be passed via the stack.
    //
    // Since `asm!` does not allow `in("rsp")` it is passed in and transferred to `rsp` in
    // the assembly code via `in(reg)`.
    //
    // The stack has to be a reference to an array of pointer-sized values and has to begin with
    // `1 (return address) + 4 (shadow space)` pointer-sized values, and is followed by all other
    // arguments that the system call receives.
    ($id:ident, $p1:ident, $p2:ident, $p3:ident, $p4:ident, stack: $stack:ident) => {
        syscall!(#2 $id, "
            xchg rsp, {0}
            mov r10, rcx
            syscall
            xchg rsp, {0}
            ",
            in(reg) $stack,
            inout("rcx") $p1 => _,
            inout("rdx") $p2 => _,
            inout("r8") $p3 => _,
            inout("r9") $p4 => _,
            out("r10") _,
            out("r11") _
        )
    };
    (#1 $id:ident, $($registers:tt)*) => {
        syscall!(#2 $id, "
            mov r10, rcx
            syscall
            ",
            out("r10") _,
            out("r11") _,
            $($registers)*
        )
    };
    (#2 $id:ident, $instructions:expr, $($registers:tt)*) => {{
        let index = match IDS {
            Some(ref ids) => ids.$id as u32,
            None => return Some(crate::error::NtStatusValue::InvalidSystemService.into())
        };

        let result: u32;
        asm!(
            $instructions,
            $($registers)*,
            inout("eax") index => result
        );

        *(&result as *const _ as *const crate::error::NtStatusResult)
    }};
}

/// Official documentation: [ntdll.NtClose](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntclose).
#[allow(non_snake_case)]
#[cfg(winapi = "syscall")]
#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) unsafe fn NtClose(
    object: crate::object::Handle
) -> crate::error::NtStatusResult {
    let object = *(&object as *const _ as *const usize);

    syscall!(close, object)
}

/// Official documentation: [ntdll.NtCreateFile](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile).
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) unsafe fn NtCreateFile(
    handle: *mut crate::object::Handle,
    // Specializations:
    // - `crate::file::DirectoryAccessModes`
    // - `crate::file::FileAccessModes`
    access_modes: u32,
    object_attributes: &crate::object::Attributes,
    io_status_block: *mut crate::io::file::IoStatusBlock,
    allocation_size: Option<&u64>,
    attributes: crate::io::file::Attributes,
    share_modes: crate::io::file::ShareModes,
    // Specializations:
    // - `crate::file::CreationDispositionDirectoryNtDll`
    // - `crate::file::CreationDispositionFileNtDll`
    creation_disposition: u32,
    creation_options: crate::io::file::CreationOptions,
    extended_attributes: Option<&crate::io::file::ntfs::ExtendedAttributesInformation>,
    extended_attributes_size: u32
) -> crate::error::NtStatusResult {
    let stack = &[
        0usize, 0, 0, 0, 0,
        *(&allocation_size as *const _ as *const usize),
        *(&attributes as *const _ as *const u32) as usize,
        *(&share_modes as *const _ as *const u32) as usize,
        creation_disposition as usize,
        *(&creation_options as *const _ as *const u32) as usize,
        *(&extended_attributes as *const _ as *const usize),
        extended_attributes_size as usize
    ];

    syscall!(create_file, handle, access_modes, object_attributes, io_status_block, stack: stack)
}

/// Official documentation: [ntdll.NtOpenProcess](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess).
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), inline(always))]
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
#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) unsafe fn NtQueryFullAttributesFile(
    attributes: &crate::object::Attributes,
    information: *mut crate::io::file::info::BasicNtDll
) -> crate::error::NtStatusResult {
    syscall!(query_full_attributes_file, attributes, information)
}

/// Official documentation: [ntdll.NtQueryInformationFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryinformationfile).
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) unsafe fn NtQueryInformationFile(
    file: crate::object::Handle,
    io_status_block: *mut crate::io::file::IoStatusBlock,
    buffer: *mut u8,
    buffer_size: u32,
    information: crate::io::file::Information,
) -> crate::error::NtStatusResult {
    let file = *(&file as *const _ as *const usize);

    let stack = &[
        0usize, 0, 0, 0, 0,
        information as usize
    ];

    syscall!(query_information_file, file, io_status_block, buffer, buffer_size, stack: stack)
}

/// Official documentation: [ntdll.NtQueryInformationProcess](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess).
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) unsafe fn NtQueryInformationProcess(
    process: crate::object::Handle,
    information: crate::process::Information,
    buffer: *mut u8,
    buffer_size: u32,
    written_size: *mut u32
) -> crate::error::NtStatusResult {
    let process = *(&process as *const _ as *const usize);
    let information = information as usize;

    let stack = &[
        0usize, 0, 0, 0, 0,
        written_size as usize
    ];

    syscall!(query_information_process, process, information, buffer, buffer_size, stack: stack)
}

/// Official documentation: [ntdll.NtQuerySystemInformation](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation).
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) unsafe fn NtQuerySystemInformation(
    information: crate::system::Information,
    buffer: *const u8,
    buffer_size: u32,
    return_size: Option<&mut u32>
) -> crate::error::NtStatusResult {
    let information = information as usize;
    let return_size = *(&return_size as *const _ as *const usize);

    syscall!(query_system_information, information, buffer, buffer_size, return_size)
}

/// Official documentation [ntdll.NtReadFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntreadfile).
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) unsafe fn NtReadFile(
    file: crate::object::Handle,
    event: Option<crate::object::Handle>,
    _apc_routine: *const u8,
    _apc_context: *const u8,
    io_status_block: *mut crate::io::file::IoStatusBlock,
    buffer: *mut u8,
    buffer_size: u32,
    offset: Option<&u64>,
    _key: Option<&u32>
) -> crate::error::NtStatusResult {
    let file = *(&file as *const _ as *const usize);
    let event = *(&event as *const _ as *const usize);

    let stack = &[
        0usize, 0, 0, 0, 0,
        io_status_block as usize,
        buffer as usize,
        buffer_size as usize,
        *(&offset as *const _ as *const usize),
        *(&_key as *const _ as *const usize)
    ];

    syscall!(read_file, file, event, _apc_routine, _apc_context, stack: stack)
}

/// Official documentation: [ntdll.NtTerminateProcess](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-zwterminateprocess).
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) unsafe fn NtTerminateProcess(
    process: crate::object::Handle,
    exit_code: u32
) -> crate::error::NtStatusResult {
    let process = *(&process as *const _ as *const usize);

    syscall!(terminate_process, process, exit_code)
}

/// Official documentation [ntdll.NtWriteFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntwritefile).
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) unsafe fn NtWriteFile(
    file: crate::object::Handle,
    event: Option<crate::object::Handle>,
    _apc_routine: *const u8,
    _apc_context: *const u8,
    io_status_block: *mut crate::io::file::IoStatusBlock,
    buffer: *const u8,
    buffer_size: u32,
    offset: Option<&u64>,
    _key: Option<&u32>
) -> crate::error::NtStatusResult {
    let file = *(&file as *const _ as *const usize);
    let event = *(&event as *const _ as *const usize);

    let stack = &[
        0usize, 0, 0, 0, 0,
        io_status_block as usize,
        buffer as usize,
        buffer_size as usize,
        *(&offset as *const _ as *const usize),
        *(&_key as *const _ as *const usize)
    ];

    syscall!(write_file, file, event, _apc_routine, _apc_context, stack: stack)
}