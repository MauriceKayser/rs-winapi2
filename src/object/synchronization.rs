//! All object synchronization related Windows types.

/// Official documentation: [Displaying a Critical Section](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/displaying-a-critical-section).
///
/// Unofficial documentation: [RTL_CRITICAL_SECTION struct](http://terminus.rewolf.pl/terminus/structures/ntdll/_RTL_CRITICAL_SECTION_combined.html).
#[repr(C)]
pub struct CriticalSection {
    debug_info: *const u8,
    lock: CriticalSectionLock,
    recursion_count: u32,
    owning_thread_id: Option<crate::process::thread::Id>,
    lock_semaphore: *const u8,
    spin_count: usize
}

/// Official documentation: [Displaying a Critical Section](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/displaying-a-critical-section).
///
/// Unofficial documentation: [RTL_CRITICAL_SECTION struct](http://terminus.rewolf.pl/terminus/structures/ntdll/_RTL_CRITICAL_SECTION_combined.html).
#[bitfield::bitfield(32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CriticalSectionLock {
    pub flags: CriticalSectionLockFlag,
    #[field(2, 30)]
    pub waiting_threads: u32
}

/// Official documentation: [Displaying a Critical Section](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/displaying-a-critical-section).
///
/// Unofficial documentation: [RTL_CRITICAL_SECTION struct](http://terminus.rewolf.pl/terminus/structures/ntdll/_RTL_CRITICAL_SECTION_combined.html).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, bitfield::Flags)]
#[repr(u8)]
pub enum CriticalSectionLockFlag {
    Locked,
    NoThreadAwoken
}

/// Stores the necessary information to manipulate an event object.
#[repr(transparent)]
pub struct Event(pub(crate) crate::object::Handle);

impl core::ops::Drop for Event {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn drop(&mut self) {
        self.0.clone().close();
    }
}