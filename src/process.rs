//! All process related Windows types.

/// Stores the necessary information to manipulate a Windows process object.
pub struct Process(crate::object::Handle);

impl Process {
    /// Returns an instance which uses a pseudo handle with all access to the current process.
    pub const fn current() -> Self {
        Self(crate::object::Handle::from(-1))
    }

    /// Official documentation: [kernel32.TerminateProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess).
    ///
    /// Tries to terminate the process.
    pub fn terminate(&self, exit_code: u32) -> Result<(), crate::error::Error> {
        #[cfg(not(any(winapi = "native", winapi = "syscall")))]
        { self.terminate_kernel32(exit_code).map_err(|e| crate::error::Error::Status(e)) }
        #[cfg(winapi = "native")]
        { self.terminate_ntdll(exit_code).map_err(|e| crate::error::Error::NtStatus(e)) }
        #[cfg(winapi = "syscall")]
        { self.terminate_syscall(exit_code).map_err(|e| crate::error::Error::NtStatus(e)) }
    }

    /// Tries to terminate the process by calling `kernel32.TerminateProcess`.
    pub fn terminate_kernel32(&self, exit_code: u32) -> Result<(), crate::error::Status> {
        unsafe { crate::error::Status::result_from_boolean(
            crate::dll::kernel32::TerminateProcess(self.0.clone(), exit_code)
        ) }
    }

    /// Tries to terminate the process by calling `ntdll.NtTerminateProcess`.
    pub fn terminate_ntdll(&self, exit_code: u32) -> Result<(), crate::error::NtStatus> {
        unsafe { crate::error::NtStatus::result_from_nt_status(
            crate::dll::ntdll::NtTerminateProcess(self.0.clone(), exit_code)
        ) }
    }

    /// Tries to terminate the process by directly calling the `ntdll.NtTerminateProcess` system
    /// call.
    pub fn terminate_syscall(&self, exit_code: u32) -> Result<(), crate::error::NtStatus> {
        unsafe { crate::error::NtStatus::result_from_nt_status(
            crate::dll::syscall::NtTerminateProcess(self.0.clone(), exit_code)
        ) }
    }
}

impl core::ops::Drop for Process {
    fn drop(&mut self) {
        if self.0.is_pseudo() { return; }

        #[cfg(not(any(winapi = "native", winapi = "syscall")))]
        unsafe { crate::dll::kernel32::CloseHandle(self.0.clone()); }
        #[cfg(winapi = "native")]
        unsafe { crate::dll::ntdll::NtClose(self.0.clone()); }
        #[cfg(winapi = "syscall")]
        unsafe { crate::dll::syscall::NtClose(self.0.clone()); }
    }
}