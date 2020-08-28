//! All heap related Windows types for the current process.

use enum_extensions::Iterator;

/// Uses the `kernel32` heap manipulation functions.
#[cfg(not(any(winapi = "native", winapi = "syscall")))]
pub type Heap = SystemHeapKernel32;

/// Uses the `ntdll` heap manipulation functions.
#[cfg(winapi = "native")]
pub type Heap = SystemHeapNtDll;

// TODO: Add Rust heap implementation for `#[cfg(winapi = "syscall")]` and remove `cfg` attribute in
//  `lib.rs`.

/// Allocator which uses the native process heap, stored in the process environment block.
pub struct SystemHeapKernel32 {
    /// If set to `true`, serialized access will not be used.
    pub no_serialize: bool,
    /// If set to `true`, memory is cleared on de-allocation.
    pub clear: bool
}

unsafe impl core::alloc::GlobalAlloc for SystemHeapKernel32 {
    #[inline(always)]
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        crate::dll::kernel32::GetProcessHeap().map(|heap| crate::dll::kernel32::HeapAlloc(
            heap,
            SystemHeapFlags::new().set(SystemHeapFlag::NoSerializeAccess, self.no_serialize),
            layout.size()
        )).unwrap_or(0 as *mut _)
    }

    #[inline(always)]
    unsafe fn dealloc(&self, memory: *mut u8, layout: core::alloc::Layout) {
        if self.clear {
            core::ptr::write_bytes(memory, 0, layout.size());
        }

        if crate::dll::kernel32::GetProcessHeap().and_then(|heap| crate::dll::kernel32::HeapFree(
            heap,
            SystemHeapFlags::new().set(SystemHeapFlag::NoSerializeAccess, self.no_serialize),
            memory
        ).into().then_some(())).is_none() {
            alloc::alloc::handle_alloc_error(layout);
        }
    }

    #[inline(always)]
    unsafe fn alloc_zeroed(&self, layout: core::alloc::Layout) -> *mut u8 {
        crate::dll::kernel32::GetProcessHeap().map(|heap| crate::dll::kernel32::HeapAlloc(
            heap,
            SystemHeapFlags::new()
                .set(SystemHeapFlag::ZeroMemory, true)
                .set(SystemHeapFlag::NoSerializeAccess, self.no_serialize),
            layout.size()
        )).unwrap_or(0 as *mut _)
    }
}

/// Allocator which uses the native process heap, stored in the process environment block.
pub struct SystemHeapNtDll {
    /// If set to `true`, serialized access will not be used.
    pub no_serialize: bool,
    /// If set to `true`, memory is cleared on de-allocation.
    pub clear: bool
}

unsafe impl core::alloc::GlobalAlloc for SystemHeapNtDll {
    #[inline(always)]
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let mut heap = core::mem::MaybeUninit::uninit();
        if crate::dll::ntdll::RtlGetProcessHeaps(1, heap.as_mut_ptr()) < 1 {
            return 0 as *mut _;
        }

        crate::dll::ntdll::RtlAllocateHeap(
            heap.assume_init(),
            SystemHeapFlags::new().set(SystemHeapFlag::NoSerializeAccess, self.no_serialize),
            layout.size()
        )
    }

    #[inline(always)]
    unsafe fn dealloc(&self, memory: *mut u8, layout: core::alloc::Layout) {
        if self.clear {
            core::ptr::write_bytes(memory, 0, layout.size());
        }

        let mut heap = core::mem::MaybeUninit::uninit();

        if crate::dll::ntdll::RtlGetProcessHeaps(1, heap.as_mut_ptr()) < 1 ||
           crate::dll::ntdll::RtlFreeHeap(
            heap.assume_init(),
            SystemHeapFlags::new().set(SystemHeapFlag::NoSerializeAccess, self.no_serialize),
            memory
        ).into().then_some(()).is_none() {
            alloc::alloc::handle_alloc_error(layout);
        }
    }

    #[inline(always)]
    unsafe fn alloc_zeroed(&self, layout: core::alloc::Layout) -> *mut u8 {
        let mut heap = core::mem::MaybeUninit::uninit();
        if crate::dll::ntdll::RtlGetProcessHeaps(1, heap.as_mut_ptr()) < 1 {
            return 0 as *mut _;
        }

        crate::dll::ntdll::RtlAllocateHeap(
            heap.assume_init(),
            SystemHeapFlags::new()
                .set(SystemHeapFlag::ZeroMemory, true)
                .set(SystemHeapFlag::NoSerializeAccess, self.no_serialize),
            layout.size()
        )
    }
}

/// Official documentation: [Heap API](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/).
#[repr(transparent)]
pub(crate) struct SystemHeapHandle(core::num::NonZeroUsize);

bitfield::bit_field!(
    /// Official documentation: [kernel32.HeapAlloc flags](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc).
    ///
    /// Official documentation: [kernel32.HeapCreate flags](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapcreate).
    #[derive(Copy, Clone, Eq, PartialEq)]
    pub(crate) SystemHeapFlags: u32;
    flags:
        pub(crate) has + pub(crate) set: SystemHeapFlag
);

/// Official documentation: [kernel32.HeapAlloc flags](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc).
///
/// Official documentation: [kernel32.HeapCreate flags](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapcreate).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, Iterator)]
#[repr(u8)]
pub(crate) enum SystemHeapFlag {
    NoSerializeAccess,
    #[allow(unused)]
    Growable,
    #[allow(unused)]
    GenerateExceptions,
    ZeroMemory,
    #[allow(unused)]
    ReallocateInPlaceOnly,
    #[allow(unused)]
    TailCheckingEnabled,
    #[allow(unused)]
    FreeCheckingEnabled,
    #[allow(unused)]
    DisableCoalesceOnFree,
    #[allow(unused)]
    Align16 = 16,
    #[allow(unused)]
    EnableTracing,
    #[allow(unused)]
    CreateEnableExecute
}