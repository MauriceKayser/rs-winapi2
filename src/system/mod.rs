//! All system related Windows types.

pub mod info;

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

/// Official documentation: [Windows release information](https://docs.microsoft.com/en-us/windows/release-health/release-information).
///
/// Unofficial documentation: [Windows 10 version history](https://en.wikipedia.org/wiki/Windows_10_version_history).
///
/// Unofficial documentation: [Windows version numbers](https://www.gaijin.at/en/infos/windows-version-numbers).
#[allow(missing_docs)]
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq)]
#[repr(u8)]
pub enum ReleaseVersion {
    Eight,
    EightDotOne,
    Ten1507,
    Ten1511,
    Ten1607,
    Ten1703,
    Ten1709,
    Ten1803,
    Ten1809,
    Ten1903,
    Ten1909,
    Ten2004,
    Ten20H2,
    Ten21H1,
    Ten21H2,
    ElevenLeaked
}

impl ReleaseVersion {
    /// Pretty printed version name.
    pub fn as_str(&self) -> &'static str {
        const MAX: usize = ReleaseVersion::ElevenLeaked as usize + 1;
        const TEXT: [&str; MAX] = [
            "8",
            "8.1",
            "10 1507",
            "10 1511",
            "10 1607",
            "10 1703",
            "10 1709",
            "10 1803",
            "10 1809",
            "10 1903",
            "10 1909",
            "10 2004",
            "10 20H2",
            "10 21H1",
            "10 21H2",
            "11 Leaked"
        ];
        TEXT[*self as usize]
    }
}

impl core::fmt::Display for ReleaseVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Official documentation: [KUSER_SHARED_DATA struct](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-kuser_shared_data).
///
/// Unofficial documentation: [KUSER_SHARED_DATA struct](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi_x/kuser_shared_data/index.htm).
#[repr(C)]
pub(crate) struct SharedData {
    tick_count_low_deprecated: u32,
    tick_count_multiplier: u32,
    time_interrupt: Time,
    time_system: Time,
    time_zone_bias: Time,
    image_number_low: u16,
    image_number_high: u16,
    nt_system_root: [crate::string::WideChar; 260],
    stack_trace_max_depth: u32,
    crypto_exponent: u32,
    time_zone_id: u32,
    large_page_minimum: u32,
    ait_sampling_value: u32,
    app_compatibility_flag: u32,
    random_number_generator_seed_version: u64,
    global_validation_run_level: u32,
    time_zone_bias_stamp: i32,
    nt_build_number: u32,
    nt_product_type: u32,
    nt_product_type_is_valid: u8,
    _pad0: u8,
    native_processor_architecture: u16,
    nt_version_major: u32,
    nt_version_minor: u32
    // TODO: Add more fields.
}

impl SharedData {
    #[allow(missing_docs)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(crate) fn get_user_mode() -> &'static Self {
        unsafe { &*(0x7FFE0000 as *const Self) }
    }

    #[allow(missing_docs, unused)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(crate) fn get_kernel_mode() -> &'static Self {
        #[cfg(target_pointer_width = "32")]
        { Self::get_kernel_mode_x32() }
        #[cfg(target_pointer_width = "64")]
        { Self::get_kernel_mode_x64() }
    }

    #[allow(missing_docs, unused)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(crate) fn get_kernel_mode_x32() -> &'static Self {
        unsafe { &*(0xFFDF0000 as *const Self) }
    }

    #[allow(missing_docs, unused)]
    #[cfg(target_pointer_width = "64")]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(crate) fn get_kernel_mode_x64() -> &'static Self {
        unsafe { &*(0xFFFFF780_00000000 as *const Self) }
    }
}

/// Unofficial documentation: [KSYSTEM_TIME struct](https://www.vergiliusproject.com/kernels/x64/Windows%2011/Insider%20Preview%20(Jun%202021)/_KSYSTEM_TIME).
#[repr(C)]
struct Time {
    low_part: u32,
    high_1_time: i32,
    high_2_time: i32
}

/// Stores the information about a Windows system version.
#[allow(missing_docs)]
pub enum Version {
    /// One of the official Windows versions.
    Official(ReleaseVersion),

    /// Unknown Windows 10 version.
    Ten { build_number: u32 },

    /// Newer than Windows 10.
    New { build_number: u32 },

    /// Older than Windows 8.
    BeforeEight { major: u32, minor: u32 }
}

impl Version {
    /// Returns the current Windows system version.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn current() -> Self {
        let env = SharedData::get_user_mode();

        match (env.nt_version_major, env.nt_version_minor) {
            (10, 0) => match env.nt_build_number {
                21996 => Self::Official(ReleaseVersion::ElevenLeaked),
                19044 => Self::Official(ReleaseVersion::Ten21H2),
                19043 => Self::Official(ReleaseVersion::Ten21H1),
                19042 => Self::Official(ReleaseVersion::Ten20H2),
                19041 => Self::Official(ReleaseVersion::Ten2004),
                18363 => Self::Official(ReleaseVersion::Ten1909),
                18362 => Self::Official(ReleaseVersion::Ten1903),
                17763 => Self::Official(ReleaseVersion::Ten1809),
                17134 => Self::Official(ReleaseVersion::Ten1803),
                16299 => Self::Official(ReleaseVersion::Ten1709),
                15063 => Self::Official(ReleaseVersion::Ten1703),
                14393 => Self::Official(ReleaseVersion::Ten1607),
                10586 => Self::Official(ReleaseVersion::Ten1511),
                10240 => Self::Official(ReleaseVersion::Ten1507),
                _ => Self::Ten { build_number: env.nt_build_number }
            },

            _ if env.nt_version_major >= 10 => Self::New { build_number: env.nt_build_number },

            (6, 3) => Self::Official(ReleaseVersion::EightDotOne),
            (6, 2) => Self::Official(ReleaseVersion::Eight),

            _ => Self::BeforeEight { major: env.nt_version_major, minor: env.nt_version_minor }
        }
    }
}

impl core::fmt::Debug for Version {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Version::Official(ty) => f.write_fmt(format_args!("Windows {}", ty)),
            Version::Ten { build_number } => f.write_fmt(format_args!("Windows 10 build {}", build_number)),
            Version::New { build_number } => f.write_fmt(format_args!("Windows 10+ build {}", build_number)),
            Version::BeforeEight { major, minor } => f.write_fmt(format_args!("Windows {}.{}", major, minor))
        }
    }
}