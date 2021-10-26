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

/// Official documentation: [TEB struct](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb).
///
/// Unofficial documentation: [TEB struct](https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/teb/index.htm).
#[allow(missing_docs)]
#[repr(C)]
pub struct EnvironmentBlock<'a> {
    exception_list: *const u8,

    /// The memory page after the stack, f.e. 0x12345000.
    pub stack_base: *const u8,

    /// The lowest memory address that belongs to the stack, f.e. 0x12340000.
    pub stack_limit: *mut u8,

    /// Posix and other subsystems related data.
    sub_system_tib: *const u8,
    fiber_data: *const u8,
    arbitrary_user_data: *const u8,
    pub this: Option<&'a mut Self>,
    environment: *const u8,
    pub client_id: super::ClientId,
    active_rpc: Option<crate::object::Handle>,
    local_storage: *const u8,
    pub process_environment_block: Option<&'a mut super::EnvironmentBlock<'a>>,
    pub last_error: crate::error::StatusResult
    // TODO: Add more fields.
}

impl<'a> EnvironmentBlock<'a> {
    /// Reads data from the "current thread" segment selector.
    #[cfg_attr(not(debug_assertions), inline(always))]
    unsafe fn read_current_ptr_mut(offset: usize) -> *mut u8 {
        let result;

        #[cfg(target_arch = "x86")]
        asm!(
            "mov {0}, fs:[{1}]",
            out(reg) result,
            in(reg) offset
        );

        #[cfg(target_arch = "x86_64")]
        asm!(
            "mov {0}, gs:[{1}]",
            out(reg) result,
            in(reg) offset
        );

        result
    }

    /// Read from the segment selector base field.
    ///
    /// The necessary instruction is supported only in 64-bit mode.
    #[cfg(target_arch = "x86_64")]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub unsafe fn current_from_segment_base() -> Option<&'static mut Self> {
        let result: *const u8;

        asm!(
            "rdgsbase {0}",
            out(reg) result
        );

        (result as *mut Self).as_mut()
    }

    /// Read from the current TEB.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub unsafe fn current_from_block() -> Option<&'static mut Self> {
        (Self::read_current_ptr_mut(offset_of!(Self, this)) as *mut Self).as_mut()
    }

    /// Read from the current TEB.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub unsafe fn current_process_environment_block()
        -> Option<&'static mut super::EnvironmentBlock<'a>>
    {
        (Self::read_current_ptr_mut(
            offset_of!(Self, process_environment_block)
        ) as *mut super::EnvironmentBlock).as_mut()
    }
}

/// The identifier (kernel handle) of a thread object.
#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(transparent)]
pub struct Id(crate::object::Id);

impl core::fmt::Debug for Id {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_block_current() {
        unsafe {
            let from_block = EnvironmentBlock::current_from_block().unwrap();
            let from_this = from_block.this.as_deref().unwrap();

            assert_ne!(from_block as *const _ as usize, 0);
            assert_eq!(from_block as *const _ as usize, from_this as *const _ as usize);

            #[cfg(target_arch = "x86_64")]
            {
                let from_base = EnvironmentBlock::current_from_segment_base().unwrap();
                assert_eq!(from_base as *const _ as usize, from_block as *const _ as usize);
            }
        }
    }

    #[test]
    fn environment_block_field_stack() {
        unsafe {
            let teb = EnvironmentBlock::current_from_block().unwrap();

            assert!((teb.stack_limit as usize) < teb.stack_base as usize);
            assert!((&teb as *const _ as usize) >= teb.stack_limit as usize);
            assert!((&teb as *const _ as usize) < teb.stack_base as usize);
        }
    }

    #[test]
    fn environment_block_field_client_id() {
        unsafe {
            let teb = EnvironmentBlock::current_from_block().unwrap();

            assert!(teb.client_id.process.is_some());
            assert_eq!(
                crate::Process::current().information_ntdll().unwrap().id,
                teb.client_id.process
            );
            assert_ne!(teb.client_id.thread, None);
        }
    }

    #[test]
    fn environment_block_field_process_environment_block() {
        unsafe {
            let teb = EnvironmentBlock::current_from_block().unwrap();
            let from_field = teb.process_environment_block.as_deref();
            let direct = EnvironmentBlock::current_process_environment_block();

            assert_ne!(teb as *const _ as usize, 0);
            assert_eq!(
                from_field.map(|v| v as *const _ as usize),
                direct.map(|v| v as *const _ as usize)
            );
        }
    }

    #[test]
    fn environment_block_field_last_error() {
        unsafe {
            let teb = EnvironmentBlock::current_from_block().unwrap();
            let from_teb = teb.last_error;

            assert_eq!(from_teb, crate::error::Status::last());
        }
    }
}