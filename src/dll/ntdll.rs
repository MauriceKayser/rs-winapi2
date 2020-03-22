//! Exports by the Windows dynamically loaded library `ntdll.dll`.

#[link(name = "ntdll", kind = "dylib")]
extern "system" {
    /// Official documentation: [ntdll.NtClose](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntclose).
    #[cfg(winapi = "native")]
    pub(crate) fn NtClose(
        object: crate::object::Handle
    ) -> crate::error::NtStatusResult;

    /// Official documentation: [ntdll.NtOpenProcess](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess).
    pub(crate) fn NtOpenProcess(
        handle: *mut Option<crate::object::Handle>,
        access_modes: crate::process::AccessModes,
        attributes: &crate::object::Attributes,
        client_id: &crate::process::ClientId
    ) -> crate::error::NtStatusResult;

    /// Official documentation: [ntdll.NtQueryInformationProcess](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess).
    pub(crate) fn NtQueryInformationProcess(
        process: crate::object::Handle,
        information: crate::process::Information,
        buffer: *mut u8,
        buffer_size: u32,
        written_size: *mut u32
    ) -> crate::error::NtStatusResult;

    /// Official documentation: [ntdll.NtQuerySystemInformation](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation).
    pub(crate) fn NtQuerySystemInformation(
        information: crate::system::Information,
        buffer: *const u8,
        buffer_size: u32,
        return_size: Option<&u32>
    ) -> Option<crate::error::NtStatus>;

    /// Official documentation: [ntdll.NtTerminateProcess](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-zwterminateprocess).
    pub(crate) fn NtTerminateProcess(
        process: crate::object::Handle,
        exit_code: u32
    ) -> crate::error::NtStatusResult;

    /// Official documentation: [ntdll.RtlAllocateHeap](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlallocateheap).
    pub(crate) fn RtlAllocateHeap(
        heap: crate::heap::SystemHeapHandle,
        flags: crate::heap::SystemHeapFlags,
        size: usize
    ) -> *mut u8;

    /// Official documentation: [ntdll.RtlFreeHeap](https://docs.microsoft.com/en-us/windows/win32/devnotes/rtlfreeheap).
    pub(crate) fn RtlFreeHeap(
        heap: crate::heap::SystemHeapHandle,
        flags: crate::heap::SystemHeapFlags,
        buffer: *mut u8
    ) -> crate::types::Boolean;

    /// Official documentation: [kernel32.GetProcessHeaps](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-getprocessheaps).
    pub(crate) fn RtlGetProcessHeaps(
        buffer_count: u32,
        buffer: *mut crate::heap::SystemHeapHandle
    ) -> u32;
}