//! All process related Windows types.

pub mod info;
pub mod thread;

use alloc::vec::Vec;
use enum_extensions::Iterator;

/// Official documentation: [Process Security and Access Rights](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights).
#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(C)]
pub struct AccessModes(bitfield::BitField32);

/// Official documentation: [Process Security and Access Rights](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights).
///
/// Unofficial documentation: [Process Hacker - ntpsapi.h](https://github.com/processhacker/processhacker/blob/master/phnt/include/ntpsapi.h).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, Iterator)]
#[repr(u8)]
pub enum AccessMode {
    Terminate,
    CreateThread,
    SetSessionId,
    VirtualMemoryOperation,
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

impl core::fmt::Debug for AccessModes {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let mut formatted = alloc::string::String::new();

        for flag in AccessMode::iter() {
            if self.0.bit(*flag as u8) {
                if formatted.len() > 0 {
                    formatted.push_str(" | ");
                }
                formatted.push_str(&alloc::format!("{:?}", flag));
            }
        }

        for flag in crate::object::AccessMode::iter() {
            if self.0.bit(*flag as u8 + 16) {
                if formatted.len() > 0 {
                    formatted.push_str(" | ");
                }
                formatted.push_str(&alloc::format!("{:?}", flag));
            }
        }

        if formatted.len() == 0 {
            formatted.push('-');
        }

        f.write_str(formatted.as_ref())
    }
}

/// Official documentation: [CLIENT_ID struct](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/a11e7129-685b-4535-8d37-21d4596ac057).
#[repr(C)]
pub struct ClientId {
    pub(crate) process: usize,
    pub(crate) thread: usize
}

impl ClientId {
    /// Creates a new instance.
    #[inline(always)]
    pub const fn new(process: u32, thread: u32) -> Self {
        Self { process: process as usize, thread: thread as usize }
    }

    /// Creates an instance from a process object id.
    #[inline(always)]
    pub const fn from_process_id(id: u32) -> Self {
        Self { process: id as usize, thread: 0 }
    }

    /// Creates an instance from a thread object id.
    #[inline(always)]
    pub const fn from_thread_id(id: u32) -> Self {
        Self { process: 0, thread: id as usize }
    }
}

/// Official documentation: [ProcessInformationClass enum](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess).
///
/// Unofficial documentation: [PROCESS_INFORMATION_CLASS enum](https://github.com/processhacker/processhacker/blob/master/phnt/include/ntpsapi.h).
#[allow(unused)]
#[derive(Copy, Clone, Debug, Iterator)]
#[repr(u32)]
pub(crate) enum Information {
    Basic,
    QuotaLimits,
    IoCounters,
    VmCounters,
    Times,
    BasePriority,
    RaisePriority,
    DebugPort,
    ExceptionPort,
    AccessToken,
    LocalDescriptorTable,
    LocalDescriptorTableSize,
    DefaultHardErrorMode,
    IoPortHandlers,
    PooledUsageAndLimits,
    WorkingSetWatch,
    UserModeIOPL,
    EnableAlignmentFaultFixup,
    PriorityClass,
    Wx86,
    HandleCount,
    AffinityMask,
    PriorityBoost,
    DeviceMap,
    Session,
    Foreground,
    Wow64,
    ImageFileName,
    LUIDDeviceMapsEnabled,
    BreakOnTermination,
    DebugObjectHandle,
    DebugFlags,
    HandleTracing,
    IoPriority,
    ExecuteFlags,
    ResourceManagement,
    Cookie,
    Image,
    CycleTime,
    PagePriority,
    InstrumentationCallback,
    ThreadStackAllocation,
    WorkingSetWatchEx,
    ImageFileNameWin32,
    ImageFileMapping,
    AffinityUpdateMode,
    MemoryAllocationMode,
    Group,
    TokenVirtualizationEnabled,
    ConsoleHostProcess,
    Window,
    Handle,
    MitigationPolicy,
    DynamicFunctionTable,
    HandleCheckingMode,
    KeepAliveCount,
    RevokeFileHandles,
    WorkingSetControl,
    HandleTable,
    CheckStackExtentsMode,
    CommandLine,
    Protection,
    MemoryExhaustion,
    Fault,
    TelemetryId,
    CommitRelease,
    DefaultCpuSets,
    AllowedCpuSets,
    SubsystemProcess,
    JobMemory,
    InPrivate,
    RaiseUMExceptionOnInvalidHandleClose,
    IumChallengeResponse,
    ChildProcess,
    HighGraphicsPriorityInformation,
    Subsystem,
    EnergyValues,
    ActivityThrottleState,
    ActivityThrottlePolicy,
    Win32kSyscallFilter,
    DisableSystemAllowedCpuSets,
    Wake,
    EnergyTrackingState,
    ManageWritesToExecutableMemory,
    CaptureTrustletLiveDump,
    TelemetryCoverage,
    Enclave,
    EnableReadWriteVmLogging,
    Uptime,
    ImageSection,
    DebugAuth,
    SystemResourceManagement,
    SequenceNumber,
    LoaderDetour,
    SecurityDomain,
    CombineSecurityDomains,
    EnableLogging,
    LeapSecond,
    FiberShadowStackAllocation,
    FreeFiberShadowStackAllocation
}

/// Stores the necessary information to manipulate a process object.
pub struct Process(crate::object::Handle);

impl Process {
    /// Returns an instance which uses a pseudo handle with all access to the current process.
    #[inline(always)]
    pub const fn current() -> Self {
        Self(crate::object::Handle::from(unsafe { core::num::NonZeroIsize::new_unchecked(-1) }))
    }

    /// Official documentation: [PROCESS_BASIC_INFORMATION struct](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess#process_basic_information).
    ///
    /// Returns basic information about the specified process.
    #[inline(always)]
    pub fn information(&self) -> Result<info::Basic, crate::error::Error> {
        #[cfg(not(any(winapi = "native", winapi = "syscall")))]
        { Self::information_kernel32(self).map_err(|e| crate::error::Error::Status(e)) }
        #[cfg(winapi = "native")]
        { Self::information_ntdll(self).map_err(|e| crate::error::Error::NtStatus(e)) }
        #[cfg(winapi = "syscall")]
        { Self::information_syscall(self).map_err(|e| crate::error::Error::NtStatus(e)) }
    }

    /// Returns basic information about the specified process.
    #[inline(always)]
    pub fn information_kernel32(&self) -> Result<info::Basic, crate::error::Status> {
        // TODO: Implement and test.
        Err(crate::error::StatusValue::CallNotImplemented.into())
    }

    /// Returns basic information about the specified process.
    #[inline(always)]
    pub fn information_ntdll(&self) -> Result<info::Basic, crate::error::NtStatus> {
        unsafe {
            let mut basic = core::mem::MaybeUninit::<info::Basic>::uninit();
            let mut _written_size = core::mem::MaybeUninit::uninit();

            match crate::dll::ntdll::NtQueryInformationProcess(
                self.0.clone(),
                Information::Basic,
                basic.as_mut_ptr() as *mut _,
                core::mem::size_of::<info::Basic>() as u32,
                _written_size.as_mut_ptr()
            ) {
                None => Ok(basic.assume_init()),
                Some(e) => Err(e)
            }
        }
    }

    /// Returns the process identifier of the specified process.
    #[inline(always)]
    pub fn information_syscall(&self) -> Result<info::Basic, crate::error::NtStatus> {
        unsafe {
            let mut basic = core::mem::MaybeUninit::<info::Basic>::uninit();
            let mut _written_size = core::mem::MaybeUninit::uninit();

            match crate::dll::syscall::NtQueryInformationProcess(
                self.0.clone(),
                Information::Basic,
                basic.as_mut_ptr() as *mut _,
                core::mem::size_of::<info::Basic>() as u32,
                _written_size.as_mut_ptr()
            ) {
                None => Ok(basic.assume_init()),
                Some(e) => Err(e)
            }
        }
    }

    /// Returns an iterator over all currently running processes.
    #[inline(always)]
    pub fn iter() -> Result<RuntimeSnapshot, crate::error::Error> {
        #[cfg(not(any(winapi = "native", winapi = "syscall")))]
        { Self::iter_kernel32().map_err(|e| crate::error::Error::Status(e)) }
        #[cfg(winapi = "native")]
        { Self::iter_ntdll().map_err(|e| crate::error::Error::NtStatus(e)) }
        #[cfg(winapi = "syscall")]
        { Self::iter_syscall().map_err(|e| crate::error::Error::NtStatus(e)) }
    }

    /// Returns an iterator over all currently running processes.
    #[inline(always)]
    pub fn iter_kernel32() -> Result<RuntimeSnapshot, crate::error::Status> {
        // TODO: Implement and test (f. e. via `CreateToolhelp32Snapshot`).
        Err(crate::error::StatusValue::CallNotImplemented.into())
    }

    /// Returns an iterator over all currently running processes.
    #[inline(always)]
    pub fn iter_ntdll() -> Result<RuntimeSnapshot, crate::error::NtStatus> {
        let mut buffer = Vec::new();

        // Call the API and calculate the needed buffer size. Repeat until the buffer is big enough.
        loop {
            let mut return_size = 0;

            match unsafe { crate::dll::ntdll::NtQuerySystemInformation(
                crate::system::Information::Process,
                buffer.as_ptr(),
                buffer.capacity() as u32,
                Some(&mut return_size)
            ) } {
                Some(e) if e == crate::error::NtStatusValue::InfoLengthMismatch.into() => {
                    buffer.reserve(return_size as usize - buffer.capacity());
                },
                Some(e) => return Err(e),
                None => {
                    unsafe { buffer.set_len(return_size as usize); }
                    break;
                }
            }
        }

        Ok(RuntimeSnapshot { buffer })
    }

    /// Returns an iterator over all currently running processes.
    #[inline(always)]
    pub fn iter_syscall() -> Result<RuntimeSnapshot, crate::error::NtStatus> {
        let mut buffer = Vec::new();

        // Call the API and calculate the needed buffer size. Repeat until the buffer is big enough.
        loop {
            let mut return_size = 0;

            match unsafe { crate::dll::syscall::NtQuerySystemInformation(
                crate::system::Information::Process,
                buffer.as_ptr(),
                buffer.capacity() as u32,
                Some(&mut return_size)
            ) } {
                Some(e) if e == crate::error::NtStatusValue::InfoLengthMismatch.into() => {
                    buffer.reserve(return_size as usize - buffer.capacity());
                },
                Some(e) => return Err(e),
                None => {
                    unsafe { buffer.set_len(return_size as usize); }
                    break;
                }
            }
        }

        Ok(RuntimeSnapshot { buffer })
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
            None => Err(crate::error::Status::last().unwrap())
        }
    }

    /// Tries to open an existing local process object.
    #[inline(always)]
    pub fn open_ntdll(
        client_id: &ClientId,
        access_modes: AccessModes,
        attributes: &crate::object::Attributes
    ) -> Result<Self, crate::error::NtStatus> {
        let mut handle = core::mem::MaybeUninit::uninit();

        unsafe { crate::dll::ntdll::NtOpenProcess(
            handle.as_mut_ptr(), access_modes, attributes, client_id
        ).map(|e| Err(e)).unwrap_or_else(|| Ok(Self(handle.assume_init()))) }
    }

    /// Tries to open an existing local process object.
    #[inline(always)]
    pub fn open_syscall(
        client_id: &ClientId,
        access_modes: AccessModes,
        attributes: &crate::object::Attributes
    ) -> Result<Self, crate::error::NtStatus> {
        let mut handle = core::mem::MaybeUninit::uninit();

        unsafe { crate::dll::syscall::NtOpenProcess(
            handle.as_mut_ptr(), access_modes, attributes, client_id
        ).map(|e| Err(e)).unwrap_or_else(|| Ok(Self(handle.assume_init()))) }
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
    #[inline(always)]
    fn drop(&mut self) {
        self.0.clone().close();
    }
}

/// Stores a snapshot of all currently running processes.
pub struct RuntimeSnapshot {
    buffer: Vec<u8>
}

impl RuntimeSnapshot {
    /// Creates an iterator over the processes in the snapshot.
    #[inline(always)]
    pub const fn iter(&self, include_threads: bool) -> RuntimeSnapshotIterator {
        RuntimeSnapshotIterator { snapshot: &self, index: 0, include_threads, is_done: false }
    }
}

/// Iterator over the processes in a `RuntimeSnapshot`.
pub struct RuntimeSnapshotIterator<'a> {
    snapshot: &'a RuntimeSnapshot,
    index: usize,

    include_threads: bool,
    is_done: bool
}

impl<'a> core::iter::Iterator for RuntimeSnapshotIterator<'a> {
    type Item = RuntimeInformation<'a>;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        if self.is_done { return None; }

        // Cast the buffer to an `InformationProcess` struct.
        let process: &crate::system::InformationProcess = unsafe {
            crate::conversion::cast(&self.snapshot.buffer[self.index..])?
        };

        let mut threads = Vec::new();
        let mut index = core::mem::size_of_val(process);

        if self.include_threads {
            for _ in 0..process.thread_count {
                // Cast the buffer to an `InformationThread` struct.
                let thread: &crate::system::InformationThread = unsafe {
                    crate::conversion::cast(&self.snapshot.buffer[self.index + index..])?
                };

                threads.push(thread);
                index += core::mem::size_of_val(thread);
            }
        }

        // Add the offset to the index, if the offset is `0` set the status to `done`.
        match process.next_offset {
            Some(next_offset) => self.index += next_offset.get() as usize,
            None => self.is_done = true
        }

        Some(RuntimeInformation { process, threads })
    }
}

/// Stores information about a process in a `RuntimeSnapshot`.
#[derive(Debug)]
pub struct RuntimeInformation<'a> {
    /// Stores information about the process.
    pub process: &'a crate::system::InformationProcess<'a>,

    /// Optionally stores information about the process's threads, if `include_threads` was
    /// set to `true` when calling `RuntimeSnapshot::iter`.
    pub threads: Vec<&'a crate::system::InformationThread>
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::string::ImplString;

    #[test]
    fn process_kernel32() {
        let me = Process::current();

        assert_eq!(
            me.information_kernel32().err(),
            Some(crate::error::StatusValue::CallNotImplemented.into())
        );

        // TODO: Implement.
    }

    #[test]
    fn process_ntdll() {
        let me_all = Process::current();
        let info_all = me_all.information_ntdll().unwrap();
        let snapshot = Process::iter_ntdll().unwrap();

        let snap_me = snapshot.iter(true).filter(
            |entry| entry.process.id() == info_all.id()
        ).collect::<Vec<_>>();

        assert_eq!(snap_me.len(), 1);

        let snap_me = snap_me.first().unwrap();

        assert!(snap_me.threads.len() > 0);
        assert!(snap_me.process.image_name().starts_with("winapi2-"));
        assert!(snap_me.process.image_name().ends_with(".exe"));

        let me_limited = Process::open_ntdll(
            &ClientId::from_process_id(info_all.id()),
            AccessModes::new().set(AccessMode::QueryLimitedInformation, true),
            &crate::object::Attributes::new(
                None,
                None,
                crate::object::AttributeFlags::new(),
                None,
                None
            )
        ).unwrap();
        let info_limited = me_limited.information_ntdll().unwrap();

        assert_eq!(info_all.id(), info_limited.id());
    }

    #[test]
    fn process_syscall() {
        crate::init_syscall_ids();

        let me_all = Process::current();
        let info_all = me_all.information_syscall().unwrap();
        let snapshot = Process::iter_syscall().unwrap();

        let snap_me = snapshot.iter(true).filter(
            |entry| entry.process.id() == info_all.id()
        ).collect::<Vec<_>>();

        assert_eq!(snap_me.len(), 1);

        let snap_me = snap_me.first().unwrap();

        assert!(snap_me.threads.len() > 0);
        assert!(snap_me.process.image_name().starts_with("winapi2-"));
        assert!(snap_me.process.image_name().ends_with(".exe"));

        let me_limited = Process::open_syscall(
            &ClientId::from_process_id(info_all.id()),
            AccessModes::new().set(AccessMode::QueryLimitedInformation, true),
            &crate::object::Attributes::new(
                None,
                None,
                crate::object::AttributeFlags::new(),
                None,
                None
            )
        ).unwrap();
        let info_limited = me_limited.information_syscall().unwrap();

        assert_eq!(info_all.id(), info_limited.id());
    }
}