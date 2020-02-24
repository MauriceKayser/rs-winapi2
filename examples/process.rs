#![windows_subsystem = "windows"]

fn main() {
    #[cfg(target_arch = "x86")]
    unsafe {
        // Windows 10 Professional x86 v1909.
        winapi2::SYSCALL_IDS = Some(winapi2::SyscallIds {
            close: 0x18D,
            terminate_process: 0x24
        });
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // Windows 10 Professional x86_64 v1909.
        winapi2::SYSCALL_IDS = Some(winapi2::SyscallIds {
            close: 0x0F,
            terminate_process: 0x2C
        });
    }

    let process = winapi2::Process::current();
    let _ = process.terminate(1);
    let _ = process.terminate_kernel32(2);
    let _ = process.terminate_ntdll(3);
    let _ = process.terminate_syscall(4);
}