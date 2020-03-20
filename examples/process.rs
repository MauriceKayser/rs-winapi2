extern crate alloc;

use winapi2::process::*;

fn main() {
    // Must be the done before any syscall related `winapi2` function is called.
    initialize_syscall_ids();

    print_self_info();
    try_terminate_system();
}

fn initialize_syscall_ids() {
    #[cfg(target_arch = "x86")]
    unsafe {
        // Windows 10 Professional x86 v1909.
        winapi2::SYSCALL_IDS = Some(winapi2::SyscallIds {
            close: 0x18D,
            open_process: 0xE9,
            query_information_process: 0xB9,
            terminate_process: 0x24
        });
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // Windows 10 Professional x86_64 v1909.
        winapi2::SYSCALL_IDS = Some(winapi2::SyscallIds {
            close: 0x0F,
            open_process: 0x26,
            query_information_process: 0x19,
            terminate_process: 0x2C
        });
    }
}

fn print_self_info() {
    winapi2::print!("Querying information.. ");

    let information = Process::current().information_syscall().expect(
        "could not query basic information"
    );

    winapi2::println!("I am: {}, parent is {}.", information.id(), information.inherited_from_id());
}

fn try_terminate_system() {
    winapi2::print!("Opening SYSTEM process.. ");

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
    ).expect("could not open SYSTEM process, I might not be admin");

    winapi2::print!("\nTrying to terminate.. ");

    process.terminate(1).expect("did not expect to terminate the SYSTEM process");
    process.terminate_kernel32(2).expect("did not expect to terminate the SYSTEM process");
    process.terminate_ntdll(3).expect("did not expect to terminate the SYSTEM process");
    process.terminate_syscall(4).expect("did not expect to terminate the SYSTEM process");

    winapi2::println!("did not terminate, as expected.");
}