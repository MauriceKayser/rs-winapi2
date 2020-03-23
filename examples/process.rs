extern crate alloc;

use winapi2::process::*;

fn main() {
    // Must be the done before any syscall related `winapi2` function is called.
    winapi2::SyscallIds::initialize_10_1909();

    winapi2::print!("1. ");
    print_self_info();

    winapi2::print!("2. ");
    try_terminate_system();

    winapi2::print!("3. ");
    list_processes();
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

    winapi2::print!("Trying to terminate.. ");

    process.terminate(1).expect("did not expect to terminate the SYSTEM process");
    process.terminate_kernel32(2).expect("did not expect to terminate the SYSTEM process");
    process.terminate_ntdll(3).expect("did not expect to terminate the SYSTEM process");
    process.terminate_syscall(4).expect("did not expect to terminate the SYSTEM process");

    winapi2::println!("did not terminate, as expected.");
}

fn list_processes() {
    winapi2::print!("Enumerating processes.. ");

    let processes = Process::iter_ntdll().expect("could not list processes");

    for entry in processes.iter(true) {
        winapi2::print!(
            "\n{:8} {} ({} thread{})",
            entry.process.id(), entry.process.image_name(),
            entry.threads.len(), if entry.threads.len() != 1 {"s"} else {""}
        );
    }
}