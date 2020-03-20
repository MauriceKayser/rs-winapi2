//! All process related Windows types.

/// Official documentation: [Process Security and Access Rights](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights).
#[repr(C)]
pub struct AccessModes(bitfield::BitField32);

/// Official documentation: [Process Security and Access Rights](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights).
#[allow(missing_docs)]
#[repr(u8)]
pub enum AccessMode {
    Terminate,
    CreateThread,
    VirtualMemoryOperation = 3,
    VirtualMemoryRead,
    VirtualMemoryWrite,
    DuplicateHandle,
    CreateProcess,
    SetQuota,
    SetInformation,
    QueryInformation,
    SuspendResume,
    QueryLimitedInformation
}

impl AccessModes {
    /// Creates a new instance.
    #[inline(always)]
    pub const fn new() -> Self {
        Self(bitfield::BitField32::new())
    }

    /// Returns a modified variant with the flag set to the specified value.
    #[inline(always)]
    pub const fn set(&self, mode: AccessMode, value: bool) -> Self {
        Self(self.0.set_bit(mode as u8, value))
    }

    /// Returns a modified variant with the standard flag set to the specified value.
    #[inline(always)]
    pub const fn set_standard(&self, mode: crate::object::AccessMode, value: bool) -> Self {
        Self(self.0.set_bit(mode as u8 + 16, value))
    }
}

/// Official documentation: [CLIENT_ID struct](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/a11e7129-685b-4535-8d37-21d4596ac057).
#[repr(C)]
pub struct ClientId {
    process: usize,
    thread: usize
}

impl ClientId {
    /// Creates a new instance.
    #[inline(always)]
    pub fn new(process: u32, thread: u32) -> Self {
        Self { process: process as usize, thread: thread as usize }
    }

    /// Creates an instance from a process object id.
    #[inline(always)]
    pub fn from_process_id(id: u32) -> Self {
        Self { process: id as usize, thread: 0 }
    }

    /// Creates an instance from a thread object id.
    #[inline(always)]
    pub fn from_thread_id(id: u32) -> Self {
        Self { process: 0, thread: id as usize }
    }
}

/// Stores the necessary information to manipulate a process object.
pub struct Process(crate::object::Handle);

impl Process {
    /// Returns an instance which uses a pseudo handle with all access to the current process.
    #[inline(always)]
    pub const fn current() -> Self {
        Self(crate::object::Handle::from(-1))
    }

    /// Official documentation: [kernel32.OpenProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess).
    ///
    /// Tries to open an existing local process object.
    #[inline(always)]
    pub fn open(id: u32, access_modes: AccessModes, inherit_handles: bool)
        -> Result<Self, crate::error::Error>
    {
        #[cfg(not(any(winapi = "native", winapi = "syscall")))]
        { Self::open_kernel32(id, access_modes, inherit_handles).map_err(|e| crate::error::Error::Status(e)) }
        #[cfg(any(winapi = "native", winapi = "syscall"))]
        {
            let client_id = ClientId::from_process_id(id);
            let attributes = crate::object::Attributes::new(
                None,
                None,
                crate::object::AttributeFlags::new(),
                None,
                None
            );
            #[cfg(winapi = "native")]
            { Self::open_ntdll(&client_id, access_modes, &attributes).map_err(|e| crate::error::Error::NtStatus(e)) }
            #[cfg(winapi = "syscall")]
            { Self::open_syscall(&client_id, access_modes, &attributes).map_err(|e| crate::error::Error::NtStatus(e)) }
        }
    }

    /// Tries to open an existing local process object.
    #[inline(always)]
    pub fn open_kernel32(id: u32, access_modes: AccessModes, inherit_handles: bool)
        -> Result<Self, crate::error::Status>
    {
        let handle = unsafe { crate::dll::kernel32::OpenProcess(
            access_modes, crate::types::Boolean::from(inherit_handles), id
        ) };
        match handle {
            Some(handle) => Ok(Self(handle)),
            None => Err(unsafe { crate::dll::kernel32::GetLastError() })
        }
    }

    /// Tries to open an existing local process object.
    #[inline(always)]
    pub fn open_ntdll(
        client_id: &ClientId,
        access_modes: AccessModes,
        attributes: &crate::object::Attributes
    ) -> Result<Self, crate::error::NtStatus> {
        let mut handle = None;

        unsafe { crate::dll::ntdll::NtOpenProcess(
            &mut handle, access_modes, attributes, client_id
        ).map(|e| Err(e)).unwrap_or_else(|| Ok(Self(handle.unwrap()))) }
    }

    /// Tries to open an existing local process object.
    #[inline(always)]
    pub fn open_syscall(
        client_id: &ClientId,
        access_modes: AccessModes,
        attributes: &crate::object::Attributes
    ) -> Result<Self, crate::error::NtStatus> {
        let mut handle = None;

        unsafe { crate::dll::syscall::NtOpenProcess(
            &mut handle, access_modes, attributes, client_id
        ).map(|e| Err(e)).unwrap_or_else(|| Ok(Self(handle.unwrap()))) }
    }

    /// Official documentation: [kernel32.TerminateProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess).
    ///
    /// Tries to terminate the process.
    #[inline(always)]
    pub fn terminate(&self, exit_code: u32) -> crate::error::ErrorResult {
        #[cfg(not(any(winapi = "native", winapi = "syscall")))]
        { self.terminate_kernel32(exit_code).map(|e| crate::error::Error::Status(e)) }
        #[cfg(winapi = "native")]
        { self.terminate_ntdll(exit_code).map(|e| crate::error::Error::NtStatus(e)) }
        #[cfg(winapi = "syscall")]
        { self.terminate_syscall(exit_code).map(|e| crate::error::Error::NtStatus(e)) }
    }

    /// Tries to terminate the process by calling `kernel32.TerminateProcess`.
    #[inline(always)]
    pub fn terminate_kernel32(&self, exit_code: u32) -> crate::error::StatusResult {
        unsafe { crate::dll::kernel32::TerminateProcess(
            self.0.clone(), exit_code
        ).to_status_result() }
    }

    /// Tries to terminate the process by calling `ntdll.NtTerminateProcess`.
    #[inline(always)]
    pub fn terminate_ntdll(&self, exit_code: u32) -> crate::error::NtStatusResult {
        unsafe { crate::dll::ntdll::NtTerminateProcess(self.0.clone(), exit_code) }
    }

    /// Tries to terminate the process by directly calling the `ntdll.NtTerminateProcess` system
    /// call.
    #[inline(always)]
    pub fn terminate_syscall(&self, exit_code: u32) -> crate::error::NtStatusResult {
        unsafe { crate::dll::syscall::NtTerminateProcess(self.0.clone(), exit_code) }
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