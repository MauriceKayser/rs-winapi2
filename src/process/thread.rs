//! All thread related Windows types.

/// Official documentation [SetProcessAffinityMask function](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setprocessaffinitymask).
#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(C)]
pub struct CpuAffinityMask(u64);

impl CpuAffinityMask {
    /// Creates a new instance with no cpu affinities set.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub const fn new() -> Self {
        Self(0)
    }

    /// Returns `true` if the affinity for the cpu is set, `false` otherwise. `index` must be < 64.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub const fn cpu(&self, index: u8) -> bool {
        // TODO: Wait for https://github.com/rust-lang/rust/issues/51999.
        // assert!(index < 64);

        ((self.0 >> index) & 1) != 0
    }

    /// Returns a new instance with the affinity for the cpu specified via `index` set to `value`.
    /// `index` must be < 64.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub const fn set_cpu(&self, index: u8, value: bool) -> Self {
        // TODO: Wait for https://github.com/rust-lang/rust/issues/51999.
        // assert!(index < 64);

        let cleared = self.0 & !(1 << index);

        Self(cleared | ((value as u64) << index))
    }
}

impl core::fmt::Debug for CpuAffinityMask {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let mut result = &mut f.debug_struct(stringify!(CpuAffinityMask));

        for i in 0..64 {
            result = result.field(&alloc::format!("Cpu{}", i), &self.cpu(i));
        }

        result.finish()
    }
}

impl core::fmt::Display for CpuAffinityMask {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let mut flags = alloc::vec::Vec::new();

        for i in 0..64 {
            if self.cpu(i) {
                flags.push(alloc::format!("{:?}", i));
            }
        }

        let flags = flags.join(" | ");

        f.write_str(if flags.len() > 0 { &flags } else { "-" })
    }
}

/// Official documentation [ThreadPriorityLevel enum](https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.threadprioritylevel).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, bitfield::FromPrimitive)]
#[repr(i32)]
pub enum PriorityLevel {
    Idle = -15,
    Lowest = -2,
    BelowNormal,
    Normal,
    AboveNormal,
    Highest,
    TimeCritical = 15
}

/// Official documentation [ThreadState enum](https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.threadstate).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, bitfield::FromPrimitive)]
#[repr(u32)]
pub enum State {
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated,
    Waiting,
    Transition,
    Unknown
}

/// Official documentation [ThreadWaitReason enum](https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.threadwaitreason).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, bitfield::FromPrimitive)]
#[repr(u32)]
pub enum WaitReason {
    Executive,
    FreePage,
    PageIn,
    SystemAllocation,
    ExecutionDelay,
    Suspended,
    UserRequest,
    EventPairHigh,
    EventPairLow,
    LpcReceive,
    LpcReply,
    VirtualMemory,
    PageOut,
    Unknown
}