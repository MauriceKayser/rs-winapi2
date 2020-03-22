//! All thread related Windows types.

use from_primitive::FromPrimitive;

/// Official documentation [ThreadPriorityLevel enum](https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.threadprioritylevel).
#[allow(missing_docs)]
#[derive(FromPrimitive)]
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
#[derive(FromPrimitive)]
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
#[derive(FromPrimitive)]
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