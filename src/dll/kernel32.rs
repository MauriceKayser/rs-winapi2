//! Exports by the Windows dynamically loaded library `kernel32.dll`.

#[link(name = "kernel32", kind = "dylib")]
extern "system" {
    /// Official documentation: [kernel32.CloseHandle](https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle).
    pub(crate) fn CloseHandle(
        object: crate::object::Handle
    ) -> crate::types::Boolean;

    /// Official documentation: [kernel32.GetLastError](https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror).
    pub(crate) fn GetLastError() -> crate::error::Status;

    /// Official documentation: [kernel32.GetProcessHeap](https://docs.microsoft.com/en-us/windows/desktop/api/heapapi/nf-heapapi-getprocessheap).
    pub(crate) fn GetProcessHeap() -> Option<crate::heap::SystemHeapHandle>;

    /// Official documentation: [kernel32.HeapAlloc](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc).
    pub(crate) fn HeapAlloc(
        heap: crate::heap::SystemHeapHandle,
        flags: crate::heap::SystemHeapFlags,
        size: usize
    ) -> *mut u8;

    /// Official documentation: [kernel32.HeapFree](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapfree).
    pub(crate) fn HeapFree(
        heap: crate::heap::SystemHeapHandle,
        flags: crate::heap::SystemHeapFlags,
        buffer: *mut u8
    ) -> crate::types::Boolean;

    /// Official documentation: [kernel32.OpenProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess).
    pub(crate) fn OpenProcess(
        access_modes: crate::process::AccessModes,
        inherit_handles: crate::types::Boolean,
        id: u32
    ) -> Option<crate::object::Handle>;

    /// Official documentation: [kernel32.TerminateProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess).
    pub(crate) fn TerminateProcess(
        process: crate::object::Handle,
        exit_code: u32
    ) -> crate::types::Boolean;
}