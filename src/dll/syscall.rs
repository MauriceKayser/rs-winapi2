//! Direct implementation for the exports by several Windows dynamically loaded libraries.

/// Table that stores all system call ids which might get used by the internal functions.
#[allow(missing_docs)]
pub struct Ids {
    pub close: u16,
    pub open_process: u16,
    pub query_information_process: u16,
    pub query_system_information: u16,
    pub terminate_process: u16
}

/// Global instance of system call ids that is used by all internal functions.
pub static mut IDS: Option<Ids> = None;

impl Ids {
    /// Initializes the system call id table with the `Windows 10 1909` values.
    pub fn initialize_10_1909() {
        #[cfg(target_arch = "x86")]
        unsafe {
            // Windows 10 Professional x86 v1909.
            IDS = Some(Ids {
                close: 0x18D,
                open_process: 0xE9,
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
                open_process: 0x26,
                query_information_process: 0x19,
                query_system_information: 0x36,
                terminate_process: 0x2C
            });
        }
    }
}

// TODO: Add x86 assembly shell code variant.
// TODO: Handle more than 5 parameters (if necessary).
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
    (#2 $id:ident, $command:expr, $($input:tt)*) => {{
        let index = match IDS {
            Some(ref ids) => ids.$id,
            None => return Some(crate::error::NtStatusValue::InvalidSystemService.into())
        } as usize;

        let result: u32;
        asm!(
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

/// Official documentation: [ntdll.NtOpenProcess](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess).
#[allow(non_snake_case)]
#[inline(always)]
pub(crate) unsafe fn NtOpenProcess(
    handle: *mut crate::object::Handle,
    access_modes: crate::process::AccessModes,
    attributes: &crate::object::Attributes,
    client_id: &crate::process::ClientId
) -> crate::error::NtStatusResult {
    let access_modes = *(&access_modes as *const _ as *const u32);

    syscall!(open_process, handle, access_modes, attributes, client_id)
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