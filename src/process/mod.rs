//! All process related Windows types.

pub mod environment;
pub mod info;
pub mod memory;
pub mod thread;

use alloc::vec::Vec;

/// Official documentation: [Process Security and Access Rights](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights).
///
/// Unofficial documentation: [Process Hacker - ntpsapi.h](https://github.com/processhacker/processhacker/blob/master/phnt/include/ntpsapi.h).
#[bitfield::bitfield(32)]
#[derive(Copy, Clone, Debug, Display, Eq, PartialEq)]
pub struct AccessModes {
    pub mode: AccessMode,
    pub standard: crate::object::AccessMode
}

/// Official documentation: [Process Security and Access Rights](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights).
///
/// Unofficial documentation: [Process Hacker - ntpsapi.h](https://github.com/processhacker/processhacker/blob/master/phnt/include/ntpsapi.h).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, bitfield::Flags)]
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

/// Official documentation: [CLIENT_ID struct](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/a11e7129-685b-4535-8d37-21d4596ac057).
#[allow(missing_docs)]
#[derive(Debug)]
#[repr(C)]
pub struct ClientId {
    pub process: Option<Id>,
    pub thread: Option<thread::Id>
}

/// Unofficial documentation: [Cross-Process flags](https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/peb/crossprocessflags.htm).
///
/// Unofficial documentation: [CrossProcessFlags bit field](http://terminus.rewolf.pl/terminus/structures/ntdll/_PEB_combined.html).
#[bitfield::bitfield(32)]
#[derive(Copy, Clone, Debug, Display, Eq, PartialEq)]
pub struct CrossProcessFlags(pub CrossProcessFlag);

/// Unofficial documentation: [Cross-Process flags](https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/peb/crossprocessflags.htm).
///
/// Unofficial documentation: [CrossProcessFlags bit field](http://terminus.rewolf.pl/terminus/structures/ntdll/_PEB_combined.html).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, bitfield::Flags)]
#[repr(u8)]
pub enum CrossProcessFlag {
    InJob,
    Initializing,
    UsingVEH,
    UsingVCH,
    UsingFTH,
    PreviouslyThrottled,
    CurrentlyThrottled,
    ImagesHotPatched
}

/// Unofficial documentation: [RTL_DRIVE_LETTER_CURDIR struct](http://terminus.rewolf.pl/terminus/structures/ntdll/_RTL_DRIVE_LETTER_CURDIR_combined.html).
#[repr(C)]
pub(crate) struct DriveLetter<'a> {
    // TODO: Replace `u16` with bit field.
    flags: u16,
    length: u16,
    timestamp: u32,
    dos_path: crate::string::StringA<'a>
}

/// Official documentation: [PEB struct](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb).
///
/// Unofficial documentation: [PEB struct](https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/peb/index.htm).
///
/// Unofficial documentation: [PEB struct](http://terminus.rewolf.pl/terminus/structures/ntdll/_PEB_combined.html).
#[allow(missing_docs)]
#[repr(C)]
pub struct EnvironmentBlock<'a> {
    /// If set to `true` by `ntoskrnl.PspCreateProcess` it causes `ntdll.LdrpInitialize` to call
    /// `ntdll.LdrpForkProcess`, which will reset it to `false` again afterwards.
    inherited_address_space: u8,

    /// Causes `ntdll.LdrpRunInitializeRoutines` and `kernel32.CreateProcessInternalW` to read
    /// and handle debugging related information.
    read_image_file_exec_options: u8,
    being_debugged_: u8,
    pub flags: EnvironmentBlockFlags,

    /// Always initialized with `-1` and never read.
    mutant: *const u8,
    pub image_base_address: *const u8,
    pub loader_data: Option<&'a mut LoaderData<'a>>,
    pub parameters: Option<&'a mut Parameters<'a>>,

    /// Posix and other subsystems related data.
    sub_system_data: *mut u8,
    heap: Option<crate::heap::SystemHeapHandle>,
    pub fast_peb_lock: Option<&'a mut crate::object::synchronization::CriticalSection>,
    atl_thunk_s_list: *const u8,
    image_file_execution_options_key: *const u8,
    pub cross_process_flags: CrossProcessFlags
    // TODO: Add more fields.
}

impl<'a> EnvironmentBlock<'a> {
    #[allow(missing_docs)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub const fn being_debugged(&self) -> bool {
        self.being_debugged_ != 0
    }

    /// Read from the current TEB, through the segment selector base field.
    #[cfg(target_arch = "x86_64")]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub unsafe fn current_from_segment_base_teb() -> Option<&'static mut Self> {
        thread::EnvironmentBlock::current_from_segment_base().and_then(
            |teb| teb.process_environment_block.as_deref_mut()
        )
    }

    /// Read from the current TEB.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub unsafe fn current_from_block_teb() -> Option<&'static mut Self> {
        thread::EnvironmentBlock::current_process_environment_block()
    }
}

/// Unofficial documentation: [PEB bit field](https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/peb/bitfield.htm).
///
/// Unofficial documentation: [PEB bit field](http://terminus.rewolf.pl/terminus/structures/ntdll/_PEB_combined.html).
#[bitfield::bitfield(8)]
#[derive(Copy, Clone, Debug, Display, Eq, PartialEq)]
pub struct EnvironmentBlockFlags(pub EnvironmentBlockFlag);

/// Unofficial documentation: [PEB bit field](https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/peb/bitfield.htm).
///
/// Unofficial documentation: [PEB bit field](http://terminus.rewolf.pl/terminus/structures/ntdll/_PEB_combined.html).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, bitfield::Flags)]
#[repr(u8)]
pub enum EnvironmentBlockFlag {
    ImageUsedLargePages,
    IsProtectedProcess,
    IsImageDynamicallyRelocated,
    SkipPatchingUser32Forwarders,
    IsPackagedProcess,
    IsAppContainer,
    IsProtectedProcessLight,
    IsLongPathAware
}

/// The identifier (kernel handle) of a process object.
#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(transparent)]
pub struct Id(crate::object::Id);

impl Id {
    /// Undocumented: the system process id is `4` (index: `1`) on XP and later systems.
    pub const unsafe fn system() -> Self {
        Self(crate::object::Id::from(core::num::NonZeroUsize::new_unchecked(4)))
    }
}

impl core::fmt::Debug for Id {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

/// Official documentation: [ProcessInformationClass enum](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess).
///
/// Unofficial documentation: [PROCESS_INFORMATION_CLASS enum](https://github.com/processhacker/processhacker/blob/master/phnt/include/ntpsapi.h).
#[allow(unused)]
#[derive(Copy, Clone)]
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

/// Official documentation: [struct PEB_LDR_DATA](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data).
///
/// Unofficial documentation: [struct PEB_LDR_DATA](https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/peb_ldr_data.htm).
///
/// Unofficial documentation: [struct PEB_LDR_DATA](http://terminus.rewolf.pl/terminus/structures/ntdll/_PEB_LDR_DATA_combined.html).
#[allow(missing_docs)]
#[repr(C)]
pub struct LoaderData<'a> {
    length: u32,
    initialized_: u8,

    /// Always initialized with `None` and never read.
    ss_handle: Option<crate::object::Handle>,
    pub load_order_next: Option<&'a mut LoaderDataEntry<'a>>,
    pub load_order_previous: Option<&'a mut LoaderDataEntry<'a>>,
    pub memory_order_next: Option<&'a mut LoaderDataEntry<'a>>,
    pub memory_order_previous: Option<&'a mut LoaderDataEntry<'a>>,
    pub initialization_order_next: Option<&'a mut LoaderDataEntry<'a>>,
    pub initialization_order_previous: Option<&'a mut LoaderDataEntry<'a>>,
    pub entry_in_progress: Option<&'a mut LoaderDataEntry<'a>>,
    shutdown_in_progress_: u8,
    pub shutdown_thread_id: Option<thread::Id>
}

impl<'a> LoaderData<'a> {
    #[allow(missing_docs)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn initialized(&self) -> bool {
        self.initialized_ != 0
    }

    #[allow(missing_docs)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn shutdown_in_progress(&self) -> bool {
        self.shutdown_in_progress_ != 0
    }
}

impl<'a> core::fmt::Debug for LoaderData<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct(stringify!(LoaderData))
            .field(stringify!(initialized), &self.initialized())
            .field(stringify!(load_order_next), &self.load_order_next)
            .field(stringify!(load_order_previous), &self.load_order_previous)
            .field(stringify!(memory_order_next), &self.memory_order_next)
            .field(stringify!(memory_order_previous), &self.memory_order_previous)
            .field(stringify!(initialization_order_next), &self.initialization_order_next)
            .field(stringify!(initialization_order_previous), &self.initialization_order_previous)
            .field(stringify!(entry_in_progress), &self.entry_in_progress)
            .field(stringify!(shutdown_in_progress), &self.shutdown_in_progress())
            .field(stringify!(shutdown_thread_id), &self.shutdown_thread_id)
            .finish()
    }
}

/// Official documentation: [struct LDR_DATA_TABLE_ENTRY](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data).
///
/// Unofficial documentation: [struct LDR_DATA_TABLE_ENTRY](https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/ldr_data_table_entry.htm).
///
/// Unofficial documentation: [struct LDR_DATA_TABLE_ENTRY](http://terminus.rewolf.pl/terminus/structures/ntdll/_LDR_DATA_TABLE_ENTRY_combined.html).
#[allow(missing_docs)]
#[repr(C)]
pub struct LoaderDataEntry<'a> {
    pub load_order_next: Option<&'a mut LoaderDataEntry<'a>>,
    pub load_order_previous: Option<&'a mut LoaderDataEntry<'a>>,
    pub memory_order_next: Option<&'a mut LoaderDataEntry<'a>>,
    pub memory_order_previous: Option<&'a mut LoaderDataEntry<'a>>,
    pub initialization_order_next: Option<&'a mut LoaderDataEntry<'a>>,
    pub initialization_order_previous: Option<&'a mut LoaderDataEntry<'a>>,
    pub image_base_address: Option<&'a crate::pe::DosHeader>,
    pub image_entry_point: *const u8,
    pub image_virtual_size: u32,
    pub image_path: crate::string::StringW<'a>,
    pub image_name: crate::string::StringW<'a>,
    pub flags: LoaderDataEntryFlags,
    pub load_count: u16,
    pub tls_index: u16,
    hash_link_next: *const u8,
    hash_link_previous: *const u8,
    time_date_stamp: u32,
    image_entry_point_activation_context: *const u8,
    lock: *const u8
    // TODO: Add more fields.
}

impl<'a> core::fmt::Debug for LoaderDataEntry<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct(stringify!(LoaderDataEntry))
            .field(stringify!(load_order_next), &self.load_order_next)
            .field(stringify!(load_order_previous), &self.load_order_previous)
            .field(stringify!(memory_order_next), &self.memory_order_next)
            .field(stringify!(memory_order_previous), &self.memory_order_previous)
            .field(stringify!(initialization_order_next), &self.initialization_order_next)
            .field(stringify!(initialization_order_previous), &self.initialization_order_previous)
            .field(stringify!(image_base_address), &self.image_base_address)
            .field(stringify!(image_entry_point), &self.image_entry_point)
            .field(stringify!(image_virtual_size), &self.image_virtual_size)
            .field(stringify!(image_path), &self.image_path.as_ref())
            .field(stringify!(image_name), &self.image_name.as_ref())
            .field(stringify!(flags), &self.flags)
            .field(stringify!(load_count), &self.load_count)
            .field(stringify!(tls_index), &self.tls_index)
            .finish()
    }
}

/// Unofficial documentation: [LDR_DATA_TABLE_ENTRY bit field](http://terminus.rewolf.pl/terminus/structures/ntdll/_LDR_DATA_TABLE_ENTRY_combined.html).
#[bitfield::bitfield(32)]
#[derive(Copy, Clone, Debug, Display, Eq, PartialEq)]
pub struct LoaderDataEntryFlags(pub LoaderDataEntryFlag);

/// Unofficial documentation: [LDR_DATA_TABLE_ENTRY bit field](http://terminus.rewolf.pl/terminus/structures/ntdll/_LDR_DATA_TABLE_ENTRY_combined.html).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, bitfield::Flags)]
#[repr(u8)]
pub enum LoaderDataEntryFlag {
    PackagedBinary,
    MarkedForRemoval,
    ImageDll,
    LoadNotificationsSent,
    TelemetryEntryProcessed,
    ProcessStaticImport,
    InLegacyLists,
    InIndexes,
    ShimDll,
    InExceptionTable,
    LoadInProgress = 12,
    LoadConfigProcessed,
    EntryProcessed,
    ProtectDelayLoaded,
    DoNotCallForThreads = 18,
    ProcessAttachCalled,
    ProcessAttachFailed,
    CorDeferredValidate,
    CorImage,
    DoNotRelocate,
    CorILOnly,
    Redirected = 28,
    CompatDatabaseProcessed = 31
}

/// Official documentation: [LoadLibraryEx dwFlags parameter](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw).
#[bitfield::bitfield(32)]
#[derive(Copy, Clone, Debug, Display, Eq, PartialEq)]
pub struct LoadModuleFlags(pub LoadModuleFlag);

/// Official documentation: [LoadLibraryEx dwFlags parameter](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, bitfield::Flags)]
#[repr(u8)]
pub enum LoadModuleFlag {
    DoNotResolveDllReferences,
    AsDataFile,
    WithAlteredSearchPath = 3,
    IgnoreCodeAuthzLevel,
    AsImageResource,
    AsDataFileExclusive,
    RequireSignedTarget,
    SearchDllLoadDir,
    SearchApplicationDir,
    SearchUserDirs,
    SearchSystem32,
    SearchDefaultDirs,
    SafeCurrentDirs
}

/// Represents a PE module loaded into memory.
#[repr(transparent)]
pub struct Module(core::num::NonZeroUsize);

impl Module {
    /// Cancels out the lower two bits which can be used to store information.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn address(&self) -> usize {
        self.0.get() & !0b11
    }

    /// Returns the module as reference to a `crate::pe::DosHeader` structure.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn as_dos_header(&self) -> &crate::pe::DosHeader {
        unsafe { &*(self.address() as *const _) }
    }

    /// Returns the module as a `crate::pe::PeFile` parser structure.
    ///
    /// The parameter `virtual_size` sets the boundaries for the parser.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn as_pe_file_with_size(&self, virtual_size: usize) -> crate::pe::PeFile {
        crate::pe::PeFile::new(
            unsafe { core::slice::from_raw_parts(
                self.address() as *const _,
                virtual_size
            ) },
            if self.is_data_file() { unimplemented!() } // TODO: Implement `File` parsing mode.
            else { crate::pe::ParsingMode::Virtual }
        )
    }

    /// Returns the module as a `crate::pe::PeFile` parser structure.
    ///
    /// If the virtual size of the PE file is know, prefer using `as_pe_file_with_size` instead.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn as_pe_file(&self) -> crate::pe::PeFile {
        #[cfg(not(any(winapi = "native", winapi = "syscall")))]
        { self.as_pe_file_kernel32() }
        #[cfg(winapi = "native")]
        { self.as_pe_file_ntdll() }
        #[cfg(winapi = "syscall")]
        { self.as_pe_file_syscall() }
    }

    /// Returns the module as a `crate::pe::PeFile` parser structure.
    ///
    /// If the virtual size of the PE file is know, prefer using `as_pe_file_with_size` instead.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn as_pe_file_kernel32(&self) -> crate::pe::PeFile {
        let base = self.address();
        let mut size = 0usize;

        for memory in Process::current().iter_memory_information_kernel32(base) {
            if memory.allocation_base == base {
                size = unsafe { size.unchecked_add(memory.region_size) };
            } else { break; }
        }

        self.as_pe_file_with_size(size)
    }

    /// Returns the module as a `crate::pe::PeFile` parser structure.
    ///
    /// If the virtual size of the PE file is know, prefer using `as_pe_file_with_size` instead.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn as_pe_file_ntdll(&self) -> crate::pe::PeFile {
        let base = self.address();
        let mut size = 0usize;

        for memory in Process::current().iter_memory_information_ntdll(base) {
            if memory.allocation_base == base {
                size = unsafe { size.unchecked_add(memory.region_size) };
            } else { break; }
        }

        self.as_pe_file_with_size(size)
    }

    /// Returns the module as a `crate::pe::PeFile` parser structure.
    ///
    /// If the virtual size of the PE file is know, prefer using `as_pe_file_with_size` instead.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn as_pe_file_syscall(&self) -> crate::pe::PeFile {
        let base = self.address();
        let mut size = 0usize;

        for memory in Process::current().iter_memory_information_syscall(base) {
            if memory.allocation_base == base {
                size = unsafe { size.unchecked_add(memory.region_size) };
            } else { break; }
        }

        self.as_pe_file_with_size(size)
    }

    /// Returns `true` is the module was loaded with the `AsDataFile` or `AsDataFileExclusive` flag.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub const fn is_data_file(&self) -> bool {
        self.0.get() & (1 << 0) != 0
    }

    /// Returns `true` is the module was loaded with the `AsImageResource` flag.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub const fn is_image_mapping(&self) -> bool {
        self.0.get() & (1 << 1) != 0
    }

    /// Returns the address of a module, after it is loaded into the current process.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn load_kernel32(name: &crate::string::Str, flags: LoadModuleFlags) -> Option<Self> {
        unsafe { crate::dll::kernel32::LoadLibraryExW(name.as_ptr(), 0, flags) }
    }

    // TODO: Implement `load_ntdll` & `load_syscall`.
}

impl core::ops::Drop for Module {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn drop(&mut self) {
        let closed = unsafe { crate::dll::kernel32::FreeLibrary(
            Self(core::num::NonZeroUsize::new_unchecked(self.address()))
        ) };
        debug_assert!(closed.as_bool());
    }
}

/// Official documentation: [RTL_USER_PROCESS_PARAMETERS struct](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters).
///
/// Unofficial documentation: [RTL_USER_PROCESS_PARAMETERS struct](http://terminus.rewolf.pl/terminus/structures/ntdll/_RTL_USER_PROCESS_PARAMETERS_combined.html).
#[allow(missing_docs)]
#[repr(C)]
pub struct Parameters<'a> {
    maximum_length: u32,
    length: u32,
    pub flags: ParametersFlags,
    debug_flags_: crate::types::Boolean,
    console: Option<crate::object::Handle>,
    pub console_flags: ParametersConsoleFlags,
    console_standard_input: Option<crate::object::Handle>,
    console_standard_output: Option<crate::object::Handle>,
    console_standard_error: Option<crate::object::Handle>,
    pub current_directory_path: crate::string::StringW<'a>,
    current_directory_handle: Option<crate::object::Handle>,
    pub image_path: crate::string::StringW<'a>,
    pub image_name: crate::string::StringW<'a>,
    pub command_line: crate::string::StringW<'a>,
    environment: *const u8,
    pub starting_x: u32,
    pub starting_y: u32,
    pub count_x: u32,
    pub count_y: u32,
    pub count_chars_x: u32,
    pub count_chars_y: u32,
    pub fill_attribute: crate::gui::FillAttributes,
    pub usage_flags: ParametersUsageFlags,
    pub window_visibility: crate::gui::WindowVisibility,
    pub window_title: crate::string::StringW<'a>,
    pub desktop_info: crate::string::StringW<'a>,
    pub shell_info: crate::string::StringW<'a>,
    pub runtime_data: crate::string::StringW<'a>,
    current_directories: [DriveLetter<'a>; 32],
    environment_size: usize,
    environment_version: usize,
    package_dependency_data: *const u8,
    pub process_group_id: u32,
    pub loader_threads: u32
}

impl<'a> Parameters<'a> {
    #[allow(missing_docs)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub const fn debug_flags(&self) -> bool {
        self.debug_flags_.as_bool()
    }
}

impl<'a> core::fmt::Debug for Parameters<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct(stringify!(Parameters))
            .field(stringify!(flags), &self.flags)
            .field(stringify!(debug_flags), &self.debug_flags())
            .field(stringify!(console_flags), &self.console_flags)
            .field(stringify!(current_directory_path), &self.current_directory_path.as_ref())
            .field(stringify!(image_path), &self.image_path.as_ref())
            .field(stringify!(image_name), &self.image_name.as_ref())
            .field(stringify!(command_line), &self.command_line.as_ref())
            .field(stringify!(starting_x), &self.starting_x)
            .field(stringify!(starting_y), &self.starting_y)
            .field(stringify!(count_x), &self.count_x)
            .field(stringify!(count_y), &self.count_y)
            .field(stringify!(count_chars_x), &self.count_chars_x)
            .field(stringify!(count_chars_y), &self.count_chars_y)
            .field(stringify!(fill_attribute), &self.fill_attribute)
            .field(stringify!(usage_flags), &self.usage_flags)
            .field(stringify!(window_visibility), &self.window_visibility)
            .field(stringify!(window_title), &self.window_title.as_ref())
            .field(stringify!(desktop_info), &self.desktop_info.as_ref())
            .field(stringify!(shell_info), &self.shell_info.as_ref())
            .field(stringify!(runtime_data), &self.runtime_data.as_ref())
            .field(stringify!(process_group_id), &self.process_group_id)
            .field(stringify!(loader_threads), &self.loader_threads)
            .finish()
    }
}

/// Console related parameters for a process.
#[bitfield::bitfield(32)]
#[derive(Copy, Clone, Debug, Display, Eq, PartialEq)]
pub struct ParametersConsoleFlags(pub ParametersConsoleFlag);

/// Console related parameters for a process.
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, bitfield::Flags)]
#[repr(u8)]
pub enum ParametersConsoleFlag {
    IgnoreCtrlC
}

/// Unofficial documentation: [RTL_USER_PROC_* flags](https://github.com/processhacker/processhacker/blob/master/phnt/include/ntrtl.h).
#[bitfield::bitfield(32)]
#[derive(Copy, Clone, Debug, Display, Eq, PartialEq)]
pub struct ParametersFlags(pub ParametersFlag);

/// Unofficial documentation: [RTL_USER_PROC_* flags](https://github.com/processhacker/processhacker/blob/master/phnt/include/ntrtl.h).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, bitfield::Flags)]
#[repr(u8)]
pub enum ParametersFlag {
    Normalized,
    ProfileUser,
    ProfileKernel,
    ProfileServer,
    Reserve1Mb = 5,
    Reserve16Mb,
    CaseSensitive,
    DisableHeapCommit,
    DllRedirectionLocal = 12,
    AppManifestPresent,
    ImageKeyMissing,
    OptInProcess = 17
}

/// Official documentation: [STARTF_* flags](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfow).
#[bitfield::bitfield(32)]
#[derive(Copy, Clone, Debug, Display, Eq, PartialEq)]
pub struct ParametersUsageFlags(pub ParametersUsageFlag);

/// Official documentation: [STARTF_* flags](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfow).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, bitfield::Flags)]
#[repr(u8)]
pub enum ParametersUsageFlag {
    UseWindowVisibility,
    UseSize,
    UsePosition,
    UseCountChars,
    UseFillAttribute,
    RunFullScreen,
    ForceOnFeedback,
    ForceOffFeedback,
    UseStdHandles,
    UseHotKey,
    HasShellData,
    TitleIsLinkName,
    TitleIsAppId,
    PreventPinning,
    UntrustedSource = 15
}

/// Stores the necessary information to manipulate a process object.
pub struct Process(crate::object::Handle);

impl Process {
    /// Returns an instance which uses a pseudo handle with all access to the current process.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub const fn current() -> Self {
        Self(crate::object::Handle::from(unsafe {
            core::num::NonZeroUsize::new_unchecked(-1isize as usize)
        }))
    }

    /// Official documentation: [PROCESS_BASIC_INFORMATION struct](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess#process_basic_information).
    ///
    /// Returns basic information about the specified process.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn information(&self) -> Result<info::Basic, crate::error::Error> {
        {
			#[cfg(not(any(winapi = "native", winapi = "syscall")))]
			{ self.information_kernel32() }
			#[cfg(winapi = "native")]
			{ self.information_ntdll() }
			#[cfg(winapi = "syscall")]
			{ self.information_syscall() }
		}.map_err(|e| e.into())
    }

    /// Official documentation: [PROCESS_BASIC_INFORMATION struct](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess#process_basic_information).
    ///
    /// Returns basic information about the specified process.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn information_kernel32(&self) -> Result<info::Basic, crate::error::Status> {
        // TODO: Implement and test.
        Err(crate::error::StatusValue::CallNotImplemented.into())
    }

    /// Official documentation: [PROCESS_BASIC_INFORMATION struct](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess#process_basic_information).
    ///
    /// Returns basic information about the specified process.
    #[cfg_attr(not(debug_assertions), inline(always))]
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

    /// Official documentation: [PROCESS_BASIC_INFORMATION struct](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess#process_basic_information).
    ///
    /// Returns the process identifier of the specified process.
    #[cfg_attr(not(debug_assertions), inline(always))]
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
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn iter() -> Result<RuntimeSnapshot, crate::error::Error> {
		{
			#[cfg(not(any(winapi = "native", winapi = "syscall")))]
			{ Self::iter_kernel32() }
			#[cfg(winapi = "native")]
			{ Self::iter_ntdll() }
			#[cfg(winapi = "syscall")]
			{ Self::iter_syscall() }
		}.map_err(|e| e.into())
    }

    /// Returns an iterator over all currently running processes.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn iter_kernel32() -> Result<RuntimeSnapshot, crate::error::Status> {
        // TODO: Implement and test (f. e. via `CreateToolhelp32Snapshot`).
        Err(crate::error::StatusValue::CallNotImplemented.into())
    }

    /// Returns an iterator over all currently running processes.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn iter_ntdll() -> Result<RuntimeSnapshot, crate::error::NtStatus> {
        let mut buffer = Vec::new();

        // Call the API and calculate the needed buffer size. Repeat until the buffer is big enough.
        loop {
            let mut return_size = core::mem::MaybeUninit::uninit();

            unsafe { match crate::dll::ntdll::NtQuerySystemInformation(
                crate::system::Information::Process,
                buffer.as_ptr(),
                buffer.capacity() as u32,
                return_size.as_mut_ptr()
            ) {
                Some(e) if e == crate::error::NtStatusValue::InfoLengthMismatch.into() => {
                    buffer.reserve(return_size.assume_init() as usize - buffer.capacity());
                },
                Some(e) => return Err(e),
                None => {
                    buffer.set_len(return_size.assume_init() as usize);
                    break;
                }
            } }
        }

        Ok(RuntimeSnapshot { buffer })
    }

    /// Returns an iterator over all currently running processes.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn iter_syscall() -> Result<RuntimeSnapshot, crate::error::NtStatus> {
        let mut buffer = Vec::new();

        // Call the API and calculate the needed buffer size. Repeat until the buffer is big enough.
        loop {
            let mut return_size = core::mem::MaybeUninit::uninit();

            unsafe { match crate::dll::syscall::NtQuerySystemInformation(
                crate::system::Information::Process,
                buffer.as_ptr(),
                buffer.capacity() as u32,
                return_size.as_mut_ptr()
            ) {
                Some(e) if e == crate::error::NtStatusValue::InfoLengthMismatch.into() => {
                    buffer.reserve(return_size.assume_init() as usize - buffer.capacity());
                },
                Some(e) => return Err(e),
                None => {
                    buffer.set_len(return_size.assume_init() as usize);
                    break;
                }
            } }
        }

        Ok(RuntimeSnapshot { buffer })
    }

    /// Official documentation: [kernel32.OpenProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess).
    ///
    /// Tries to open an existing local process object.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn open(id: Id, access_modes: AccessModes, inherit_handles: bool)
        -> Result<Self, crate::error::Error>
    {
		{
			#[cfg(not(any(winapi = "native", winapi = "syscall")))]
			{ Self::open_kernel32(id, access_modes, inherit_handles) }
			#[cfg(any(winapi = "native", winapi = "syscall"))]
			{
				let client_id = ClientId { process: Some(id), thread: None };
				let attributes = crate::object::Attributes::new(
					None,
					None,
					crate::object::AttributeFlags::new()
                        .set(crate::object::AttributeFlag::Inherit, inherit_handles),
					None,
					None
				);
				#[cfg(winapi = "native")]
				{ Self::open_ntdll(&client_id, access_modes, &attributes) }
				#[cfg(winapi = "syscall")]
				{ Self::open_syscall(&client_id, access_modes, &attributes) }
			}
		}.map_err(|e| e.into())
    }

    /// Tries to open an existing local process object.
    ///
    /// The `id` must be `<= u32.MAX` because `OpenProcess` takes a `u32` instead of a `usize`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn open_kernel32(id: Id, access_modes: AccessModes, inherit_handles: bool)
        -> Result<Self, crate::error::Status>
    {
        #[cfg(not(target_pointer_width = "32"))]
        if id.0.value().get() as usize > u32::MAX as usize {
            return Err(crate::error::StatusValue::InvalidParameter.into());
        }

        let handle = unsafe { crate::dll::kernel32::OpenProcess(
            access_modes,
            crate::types::Boolean::from(inherit_handles),
            id.0.value().get() as usize as u32
        ) };
        match handle {
            Some(handle) => Ok(Self(handle)),
            None => Err(crate::error::Status::last().unwrap())
        }
    }

    /// Tries to open an existing local process object.
    #[cfg_attr(not(debug_assertions), inline(always))]
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
    #[cfg_attr(not(debug_assertions), inline(always))]
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
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn terminate(&self, exit_code: u32) -> crate::error::ErrorResult {
		{
			#[cfg(not(any(winapi = "native", winapi = "syscall")))]
			{ self.terminate_kernel32(exit_code) }
			#[cfg(winapi = "native")]
			{ self.terminate_ntdll(exit_code) }
			#[cfg(winapi = "syscall")]
			{ self.terminate_syscall(exit_code) }
		}.map(|e| e.into())
    }

    /// Tries to terminate the process by calling `kernel32.TerminateProcess`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn terminate_kernel32(&self, exit_code: u32) -> crate::error::StatusResult {
        unsafe { crate::dll::kernel32::TerminateProcess(
            self.0.clone(), exit_code
        ).to_status_result() }
    }

    /// Tries to terminate the process by calling `ntdll.NtTerminateProcess`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn terminate_ntdll(&self, exit_code: u32) -> crate::error::NtStatusResult {
        unsafe { crate::dll::ntdll::NtTerminateProcess(self.0.clone(), exit_code) }
    }

    /// Tries to terminate the process by directly calling the `ntdll.NtTerminateProcess` system
    /// call.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn terminate_syscall(&self, exit_code: u32) -> crate::error::NtStatusResult {
        unsafe { crate::dll::syscall::NtTerminateProcess(self.0.clone(), exit_code) }
    }

    /// Official documentation: [kernel32.TerminateProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess).
    ///
    /// Tries to terminate the current process.
    ///
    /// WARNING: This causes UB if the current process is not terminated.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub unsafe fn terminate_current(exit_code: u32) -> ! {
        #[cfg(not(any(winapi = "native", winapi = "syscall")))]
        { Self::terminate_current_kernel32(exit_code); }
        #[cfg(winapi = "native")]
        { Self::terminate_current_ntdll(exit_code); }
        #[cfg(winapi = "syscall")]
        { Self::terminate_current_syscall(exit_code); }
    }

    /// Tries to terminate the current process by calling `kernel32.TerminateProcess`.
    ///
    /// WARNING: This causes UB if the current process is not terminated.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub unsafe fn terminate_current_kernel32(exit_code: u32) -> ! {
        crate::dll::kernel32::TerminateProcess(Self::current().0.clone(), exit_code);
        core::hint::unreachable_unchecked();
    }

    /// Tries to terminate the current process by calling `ntdll.NtTerminateProcess`.
    ///
    /// WARNING: This causes UB if the current process is not terminated.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub unsafe fn terminate_current_ntdll(exit_code: u32) -> ! {
        crate::dll::ntdll::NtTerminateProcess(Self::current().0.clone(), exit_code);
        core::hint::unreachable_unchecked();
    }

    /// Tries to terminate the current process by directly calling the `ntdll.NtTerminateProcess`
    /// system call.
    ///
    /// WARNING: This causes UB if the current process is not terminated.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub unsafe fn terminate_current_syscall(exit_code: u32) -> ! {
        crate::dll::syscall::NtTerminateProcess(Self::current().0.clone(), exit_code);
        core::hint::unreachable_unchecked();
    }
}

impl core::ops::Drop for Process {
    #[cfg_attr(not(debug_assertions), inline(always))]
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
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub const fn iter(&self) -> RuntimeSnapshotIterator {
        RuntimeSnapshotIterator { snapshot: &self, index: 0, is_done: false }
    }
}

/// Iterator over the processes in a `RuntimeSnapshot`.
pub struct RuntimeSnapshotIterator<'a> {
    snapshot: &'a RuntimeSnapshot,
    index: usize,

    is_done: bool
}

impl<'a> core::iter::Iterator for RuntimeSnapshotIterator<'a> {
    type Item = RuntimeInformation<'a>;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn next(&mut self) -> Option<Self::Item> {
        if self.is_done { return None; }

        unsafe {
            // Cast the buffer to an `InformationProcess` struct.
            let process = crate::conversion::cast::<crate::system::info::Process>(
                self.snapshot.buffer.as_ref(), self.index
            )?;

            let thread_count = core::cmp::min(
                process.thread_count as usize,
                self.snapshot.buffer.len()
                    .unchecked_sub(self.index)
                    .unchecked_sub(core::mem::size_of::<crate::system::info::Process>())
                    / core::mem::size_of::<crate::system::info::Thread>()
            );

            let threads = core::slice::from_raw_parts(
                (self.snapshot.buffer.as_ptr() as usize)
                    .unchecked_add(self.index)
                    .unchecked_add(core::mem::size_of::<crate::system::info::Process>())
                    as *const crate::system::info::Thread,
                thread_count
            );

            // Add the offset to the index, if the offset is `0` set the status to `done`.
            match process.next_offset {
                Some(next_offset) => self.index += next_offset.get() as usize,
                None => self.is_done = true
            }

            Some(RuntimeInformation { process, threads })
        }
    }
}

/// Stores information about a process in a `RuntimeSnapshot`.
#[derive(Debug)]
pub struct RuntimeInformation<'a> {
    /// Stores information about the process.
    pub process: &'a crate::system::info::Process<'a>,

    /// Stores information about the process's threads.
    pub threads: &'a [crate::system::info::Thread],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::string::ImplString;

    #[test]
    fn environment_block_current() {
        unsafe {
            let from_block = EnvironmentBlock::current_from_block_teb().unwrap();
            assert_ne!(from_block as *const _ as usize, 0);

            #[cfg(target_arch = "x86_64")]
            {
                let from_base = EnvironmentBlock::current_from_segment_base_teb().unwrap();
                assert_eq!(from_base as *const _ as usize, from_block as *const _ as usize);
            }
        }
    }

    #[test]
    fn environment_block_being_debugged() {
        unsafe {
            let peb = EnvironmentBlock::current_from_block_teb().unwrap();

            assert!(!peb.being_debugged());
        }
    }

    #[test]
    fn environment_block_flags() {
        unsafe {
            let peb = EnvironmentBlock::current_from_block_teb().unwrap();

            assert_eq!(peb.flags, EnvironmentBlockFlags::new().set(
                EnvironmentBlockFlag::IsImageDynamicallyRelocated, true
            ));
        }
    }

    #[test]
    fn environment_block_loader() {
        unsafe {
            let peb = EnvironmentBlock::current_from_block_teb().unwrap();
            let loader = peb.loader_data.as_deref().unwrap();
            let ntdll = loader.
                load_order_next.as_deref().unwrap().
                load_order_next.as_deref().unwrap();
            let ntdll_name = ntdll.image_name.as_ref();

            assert_eq!(ntdll_name, "ntdll.dll");
        }
    }

    #[test]
    fn module() {
        crate::init_syscall_ids();

        let ntdll = crate::String::from("C:\\Windows\\System32\\ntdll.dll\0");
        let module = Module::load_kernel32(
            ntdll.as_ref(), LoadModuleFlags::new()
        ).unwrap();

        let ldr_entry =
            unsafe { EnvironmentBlock::current_from_block_teb() }.unwrap()
                .loader_data.as_ref().unwrap()
                // Current process image
                .load_order_next.as_ref().unwrap()
                // ntdll.dll
                .load_order_next.as_ref().unwrap();

        assert_eq!(module.as_pe_file_kernel32().image_base.len(), ldr_entry.image_virtual_size as usize);
        assert_eq!(module.as_pe_file_ntdll().image_base.len(), ldr_entry.image_virtual_size as usize);
        assert_eq!(module.as_pe_file_syscall().image_base.len(), ldr_entry.image_virtual_size as usize);
        assert_eq!(module.as_pe_file().image_base.len(), ldr_entry.image_virtual_size as usize);
    }

    #[test]
    fn process_kernel32() {
        let me = Process::current();

        assert_eq!(
            me.information_kernel32().err(),
            Some(crate::error::StatusValue::CallNotImplemented.into())
        );

        // TODO: Implement test `process_kernel32`.
    }

    #[test]
    fn process_nt() {
        const FUNCTIONS: &[(
            fn(&Process) -> Result<info::Basic, crate::error::NtStatus>,
            fn() -> Result<RuntimeSnapshot, crate::error::NtStatus>,
            fn(&ClientId, AccessModes, &crate::object::Attributes) -> Result<Process, crate::error::NtStatus>)
        ] = &[
            (Process::information_ntdll, Process::iter_ntdll, Process::open_ntdll),
            (Process::information_syscall, Process::iter_syscall, Process::open_syscall)
        ];

        for (information_nt, iter_nt, open_nt) in FUNCTIONS {
            let me_all = Process::current();
            let info_all = information_nt(&me_all).unwrap();
            let snapshot = iter_nt().unwrap();

            let snap_me = snapshot.iter().filter(
                |entry| entry.process.id == info_all.id
            ).collect::<Vec<_>>();

            assert_eq!(snap_me.len(), 1);

            let snap_me = snap_me.first().unwrap();

            assert!(snap_me.threads.len() > 0);
            assert!(snap_me.process.image_name.as_ref().starts_with("winapi2-"));
            assert!(snap_me.process.image_name.as_ref().ends_with(".exe"));

            let me_limited = open_nt(
                &ClientId { process: info_all.id, thread: None },
                AccessModes::new().set_mode(AccessMode::QueryLimitedInformation, true),
                &crate::object::Attributes::new(
                    None,
                    None,
                    crate::object::AttributeFlags::new(),
                    None,
                    None
                )
            ).unwrap();
            let info_limited = information_nt(&me_limited).unwrap();

            assert_eq!(info_all.id, info_limited.id);
        }
    }
}