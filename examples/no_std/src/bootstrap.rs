#[global_allocator]
static ALLOC: winapi2::Heap = winapi2::Heap { clear: false, no_serialize: false };

#[panic_handler]
fn rust_begin_unwind(_info: &core::panic::PanicInfo) -> ! {
    unsafe { winapi2::Process::terminate_current(
        winapi2::error::NtStatusValue::Unwind as u32
    ) }
}

#[alloc_error_handler]
fn rust_oom(_layout: core::alloc::Layout) -> ! {
    unsafe { winapi2::Process::terminate_current(
        winapi2::error::NtStatusValue::InsufficientResources as u32
    ) }
}

#[no_mangle]
extern "system" fn mainCRTStartup() -> ! {
    #[cfg(winapi = "syscall")]
    if !winapi2::SyscallIds::initialize_statically() {
        panic!("Could not initialize syscall ids!");
    }

    unsafe { winapi2::Process::terminate_current(super::main()) }
}