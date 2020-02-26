fn main() {
    #[cfg(target_arch = "x86")]
    unsafe {
        // Windows 10 Professional x86 v1909.
        winapi2::SYSCALL_IDS = Some(winapi2::SyscallIds {
            close: 0x18D,
            open_process: 0xE9,
            terminate_process: 0x24
        });
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // Windows 10 Professional x86_64 v1909.
        winapi2::SYSCALL_IDS = Some(winapi2::SyscallIds {
            close: 0x0F,
            open_process: 0x26,
            terminate_process: 0x2C
        });
    }

    use winapi2::process::*;

    let client_id = ClientId::from_process_id(4);
    let attributes = winapi2::object::Attributes::new(
        None,
        None,
        winapi2::object::AttributeFlags::new(),
        None,
        None
    );

    let process = Process::open_syscall(
        &client_id,
        AccessModes::new().set(AccessMode::QueryLimitedInformation, true),
        &attributes
    ).expect("could not open SYSTEM process");

    process.terminate(1).expect_err("did not expect to terminate the SYSTEM process");
    process.terminate_kernel32(2).expect_err("did not expect to terminate the SYSTEM process");
    process.terminate_ntdll(3).expect_err("did not expect to terminate the SYSTEM process");
    process.terminate_syscall(4).expect_err("did not expect to terminate the SYSTEM process");
}