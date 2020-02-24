//! Exports by the Windows dynamically loaded library `kernel32.dll`.

#[link(name = "kernel32", kind = "dylib")]
extern "system" {
    /// Official documentation: [kernel32.CloseHandle](https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle).
    pub(crate) fn CloseHandle(
        object: crate::object::Handle
    ) -> crate::types::Boolean;

    /// Official documentation: [kernel32.GetLastError](https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror).
    pub(crate) fn GetLastError() -> crate::error::Status;

    /// Official documentation: [kernel32.TerminateProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess).
    pub(crate) fn TerminateProcess(
        process: crate::object::Handle,
        exit_code: u32
    ) -> crate::types::Boolean;
}