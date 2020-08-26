//! All system related Windows types.

/// Official documentation: [SYSTEM_INFORMATION_CLASS enum](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation).
///
/// Unofficial documentation: [SYSTEM_INFORMATION_CLASS enum](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/class.htm).
#[allow(unused)]
#[derive(Copy, Clone, Debug)]
#[repr(u32)]
pub(crate) enum Information {
    Basic,
    Processor,
    Performance,
    TimeOfDay,
    Path,
    Process,
    CallCount,
    Device,
    ProcessorPerformance,
    Flags,
    CallTime,
    Module,
    Locks,
    StackTrace,
    PagedPool,
    NonPagedPool,
    Handle,
    Object,
    PageFile,
    VdmInstEmul,
    VdmBop,
    FileCache,
    PoolTag,
    Interrupt,
    DpcBehavior,
    FullMemory,
    LoadGdiDriver,
    UnloadGdiDriver,
    TimeAdjustment,
    SummaryMemory,
    MirrorMemory,
    PerformanceTrace,
    CrashDump,
    Exception,
    CrashDumpState,
    KernelDebugger,
    ContextSwitch,
    RegistryQuota,
    ExtendServiceTable,
    PrioritySeparation,
    VerifierAddDriver,
    VerifierRemoveDriver,
    ProcessorIdle,
    LegacyDriver,
    CurrentTimeZone,
    LookAside,
    TimeSlipNotification,
    SessionCreate,
    SessionDetach,
    Session,
    RangeStart,
    Verifier,
    VerifierThunkExtend,
    SessionProcess,
    LoadGdiDriverInSystemSpace,
    NumaProcessorMap,
    Prefetcher,
    ExtendedProcess,
    RecommendedSharedDataAlignment,
    ComPlusPackage,
    NumaAvailableMemory,
    ProcessorPower,
    EmulationBasic,
    EmulationProcessor,
    ExtendedHandle,
    LostDelayedWrite,
    BigPool,
    SessionPoolTag,
    SessionMappedView,
    HotPatch,
    ObjectSecurityMode,
    WatchdogTimerHandler,
    WatchdogTimer,
    LogicalProcessor,
    Wow64Shared,
    RegisterFirmwareTableInformationHandler,
    FirmwareTable,
    ModuleEx,
    VerifierTriage,
    Superfetch,
    MemoryList,
    FileCacheEx,
    ThreadPriorityClientId,
    ProcessorIdleCycleTime,
    VerifierCancellation,
    ProcessorPowerEx,
    RefTrace,
    SpecialPool,
    ProcessId,
    ErrorPort,
    BootEnvironment,
    Hypervisor,
    VerifierEx,
    TimeZone,
    ImageFileExecutionOptions,
    Coverage,
    PrefetchPatch,
    VerifierFaults,
    SystemPartition,
    SystemDisk,
    ProcessorPerformanceDistribution,
    NumaProximityNode,
    DynamicTimeZone,
    CodeIntegrity,
    ProcessorMicrocodeUpdate,
    ProcessorBrandString,
    VirtualAddress,
    LogicalProcessorAndGroup,
    ProcessorCycleTime,
    Store,
    RegistryAppendString,
    AitSamplingValue,
    VhdBoot,
    CpuQuota,
    NativeBasic,
    ErrorPortTimeouts,
    LowPriorityIo,
    BootEntropy,
    VerifierCounters,
    PagedPoolEx,
    SystemPtesEx,
    NodeDistance,
    AcpiAudit,
    BasicPerformance,
    QueryPerformanceCounter,
    SessionBigPool,
    BootGraphics,
    ScrubPhysicalMemory,
    BadPage,
    ProcessorProfileControlArea,
    CombinePhysicalMemory,
    EntropyInterruptTiming,
    Console,
    PlatformBinary,
    Policy,
    HypervisorProcessorCount,
    DeviceData,
    DeviceDataEnumeration,
    MemoryTopology,
    MemoryChannel,
    BootLogo,
    ProcessorPerformanceEx,
    CriticalProcessErrorLog,
    SecureBootPolicy,
    PageFileEx,
    SecureBoot,
    EntropyInterruptTimingRaw,
    PortableWorkspaceEfiLauncher,
    FullProcess,
    KernelDebuggerEx,
    BootMetadata,
    SoftReboot,
    ElamCertificate,
    OfflineDumpConfig,
    ProcessorFeatures,
    RegistryReconciliation,
    Edid,
    Manufacturing,
    EnergyEstimationConfig,
    HypervisorDetail,
    ProcessorCycleStats,
    VmGenerationCount,
    TrustedPlatformModule,
    KernelDebuggerFlags,
    CodeIntegrityPolicy,
    IsolatedUserMode,
    HardwareSecurityTestInterfaceResults,
    SingleModule,
    AllowedCpuSets,
    DmaProtection,
    InterruptCpuSets,
    SecureBootPolicyFull,
    CodeIntegrityPolicyFull,
    AffinitizedInterruptProcessor,
    RootSilo,
    CpuSet,
    CpuSetTag,
    Win32WerStartCallout,
    SecureKernelProfile,
    CodeIntegrityPlatformManifest,
    InterruptSteering,
    SupportedProcessorArchitectures,
    MemoryUsage,
    CodeIntegrityCertificate,
    PhysicalMemory,
    ControlFlowTransition,
    KernelDebuggingAllowed,
    ActivityModerationExeState,
    ActivityModerationUserSettings,
    CodeIntegrityPoliciesFull,
    CodeIntegrityUnlock,
    IntegrityQuota,
    Flush,
    ProcessorIdleMask,
    SecureDumpEncryption,
    WriteConstraint,
    KernelVaShadow,
    HypervisorSharedPage,
    FirmwareBootPerformance,
    CodeIntegrityVerification,
    FirmwarePartition,
    SpeculationControl,
    DmaGuardPolicy,
    EnclaveLaunchControl
}

/// Official documentation: [SYSTEM_PROCESS_INFORMATION struct](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/66ef46a7-504f-4696-9613-0bd8446ee225).
///
/// Unofficial documentation: [SYSTEM_PROCESS_INFORMATION struct](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/process.htm).
#[allow(missing_docs)]
#[repr(C)]
pub struct InformationProcess<'a> {
    pub(crate) next_offset: Option<core::num::NonZeroU32>,
    pub(crate) thread_count: u32,
    pub working_set_private_size: i64,
    pub hard_fault_count: u32,
    pub thread_count_high: u32,
    pub cycle_time: u64,
    pub create_time: crate::file::Time,
    pub user_time: i64,
    pub kernel_time: i64,
    image_name_: crate::string::StringW<'a>,
    base_priority_: i32,
    id_: usize,
    inherited_from_id_: usize,
    pub handle_count: u32,
    pub session_id: u32,
    pub key: usize,
    pub virtual_size_peak: usize,
    pub virtual_size: usize,
    pub page_fault_count: u32,
    pub working_set_size_peak: usize,
    pub working_set_size: usize,
    pub paged_pool_quota_size_peak: usize,
    pub paged_pool_quota_size: usize,
    pub non_paged_pool_quota_size_peak: usize,
    pub non_paged_pool_quota_size: usize,
    pub page_file_size: usize,
    pub page_file_size_peak: usize,
    pub private_page_size: usize,
    pub operation_read_count: i64,
    pub operation_write_count: i64,
    pub operation_other_count: i64,
    pub transfer_read_count: i64,
    pub transfer_write_count: i64,
    pub transfer_other_count: i64
}

impl<'a> InformationProcess<'a> {
    #[allow(missing_docs)]
    #[inline(always)]
    pub fn base_priority(&self) -> Result<crate::process::thread::PriorityLevel, i32> {
        core::convert::TryFrom::try_from(self.base_priority_)
    }

    #[allow(missing_docs)]
    #[inline(always)]
    pub const fn id(&self) -> u32 {
        self.id_ as u32
    }

    #[allow(missing_docs)]
    #[inline(always)]
    pub fn image_name(&'a self) -> &'a crate::string::Str {
        (&self.image_name_).into()
    }

    #[allow(missing_docs)]
    #[inline(always)]
    pub const fn inherited_from_id(&self) -> u32 {
        self.inherited_from_id_ as u32
    }
}

impl<'a> core::fmt::Debug for InformationProcess<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct(stringify!(InformationProcess))
            .field(stringify!(working_set_private_size), &self.working_set_private_size)
            .field(stringify!(hard_fault_count), &self.hard_fault_count)
            .field(stringify!(thread_count_high), &self.thread_count_high)
            .field(stringify!(cycle_time), &self.cycle_time)
            .field(stringify!(create_time), &self.create_time)
            .field(stringify!(user_time), &self.user_time)
            .field(stringify!(kernel_time), &self.kernel_time)
            .field(stringify!(image_name), &self.image_name())
            .field(stringify!(base_priority), &self.base_priority())
            .field(stringify!(id), &self.id())
            .field(stringify!(inherited_from_id), &self.inherited_from_id())
            .field(stringify!(handle_count), &self.handle_count)
            .field(stringify!(session_id), &self.session_id)
            .field(stringify!(key), &self.key)
            .field(stringify!(virtual_size_peak), &self.virtual_size_peak)
            .field(stringify!(virtual_size), &self.virtual_size)
            .field(stringify!(page_fault_count), &self.page_fault_count)
            .field(stringify!(working_set_size_peak), &self.working_set_size_peak)
            .field(stringify!(working_set_size), &self.working_set_size)
            .field(stringify!(paged_pool_quota_size_peak), &self.paged_pool_quota_size_peak)
            .field(stringify!(paged_pool_quota_size), &self.paged_pool_quota_size)
            .field(stringify!(non_paged_pool_quota_size_peak), &self.non_paged_pool_quota_size_peak)
            .field(stringify!(non_paged_pool_quota_size), &self.non_paged_pool_quota_size)
            .field(stringify!(page_file_size), &self.page_file_size)
            .field(stringify!(page_file_size_peak), &self.page_file_size_peak)
            .field(stringify!(private_page_size), &self.private_page_size)
            .field(stringify!(operation_read_count), &self.operation_read_count)
            .field(stringify!(operation_write_count), &self.operation_write_count)
            .field(stringify!(operation_other_count), &self.operation_other_count)
            .field(stringify!(transfer_read_count), &self.transfer_read_count)
            .field(stringify!(transfer_write_count), &self.transfer_write_count)
            .field(stringify!(transfer_other_count), &self.transfer_other_count)
            .finish()
    }
}

/// Official documentation: [SYSTEM_THREAD_INFORMATION struct](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/e82d73e4-cedb-4077-9099-d58f3459722f).
#[allow(missing_docs)]
#[repr(C)]
pub struct InformationThread {
    pub kernel_time: i64,
    pub user_time: i64,
    pub create_time: crate::file::Time,
    pub wait_time: u32,
    pub start_address: usize,
    id_: crate::process::ClientId,
    priority_: i32,
    base_priority_: i32,
    pub context_switches: u32,
    state_: u32,
    wait_reason_: u32
}

impl InformationThread {
    #[allow(missing_docs)]
    #[inline(always)]
    pub fn base_priority(&self) -> Result<crate::process::thread::PriorityLevel, i32> {
        core::convert::TryFrom::try_from(self.base_priority_)
    }

    #[allow(missing_docs)]
    #[inline(always)]
    pub const fn id(&self) -> u32 {
        self.id_.thread as u32
    }

    #[allow(missing_docs)]
    #[inline(always)]
    pub fn priority(&self) -> Result<crate::process::thread::PriorityLevel, i32> {
        core::convert::TryFrom::try_from(self.priority_)
    }

    #[allow(missing_docs)]
    #[inline(always)]
    pub fn state(&self) -> Result<crate::process::thread::State, u32> {
        core::convert::TryFrom::try_from(self.state_)
    }

    #[allow(missing_docs)]
    #[inline(always)]
    pub fn wait_reason(&self) -> Result<crate::process::thread::WaitReason, u32> {
        core::convert::TryFrom::try_from(self.wait_reason_)
    }
}

impl core::fmt::Debug for InformationThread {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct(stringify!(InformationThread))
            .field(stringify!(kernel_time), &self.kernel_time)
            .field(stringify!(user_time), &self.user_time)
            .field(stringify!(create_time), &self.create_time)
            .field(stringify!(wait_time), &self.wait_time)
            .field(stringify!(start_address), &self.start_address)
            .field(stringify!(id), &self.id())
            .field(stringify!(priority), &self.priority())
            .field(stringify!(base_priority), &self.base_priority())
            .field(stringify!(context_switches), &self.context_switches)
            .field(stringify!(state), &self.state())
            .field(stringify!(wait_reason), &self.wait_reason())
            .finish()
    }
}