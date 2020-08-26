extern crate alloc;

use winapi2::file::*;

fn main() {
    // Must be the done before any syscall related `winapi2` function is called.
    winapi2::SyscallIds::initialize_10_1909();

    winapi2::print!("1. ");
    calc_attributes();

    winapi2::print!("2. ");
    calc_information();

    winapi2::print!("3. ");
    open_calc();
}

fn calc_attributes() {
    let file_path_calc = winapi2::string::String::from(r"\??\C:\Windows\System32\calc.exe");
    let file_path_calc = winapi2::string::StringW::from(file_path_calc.as_ref());
    let object_attributes = winapi2::object::Attributes::from_name(&file_path_calc);

    let attributes = Object::attributes_syscall(&object_attributes).unwrap();
    winapi2::println!("{:?}", &attributes);
}

fn calc_information() {
    let file_path_calc = winapi2::string::String::from(r"\??\C:\Windows\System32\calc.exe");
    let file_path_calc = winapi2::string::StringW::from(file_path_calc.as_ref());
    let object_attributes = winapi2::object::Attributes::from_name(&file_path_calc);

    let information = Object::information_syscall(&object_attributes).unwrap();
    winapi2::println!("{:?}", &information);
}

fn open_calc() {
    let file_path_calc = winapi2::string::String::from(r"\??\C:\Windows\System32\calc.exe");
    let file_path_calc = winapi2::string::StringW::from(file_path_calc.as_ref());
    let object_attributes = winapi2::object::Attributes::from_name(&file_path_calc);

    let _ = winapi2::File::create_syscall(
        FileAccessModes::new().set(FileAccessMode::ReadAttributes, true),
        &object_attributes,
        None,
        Attributes::new(),
        ShareModes::all(),
        CreationDispositionFileNtDll::OpenExisting,
        CreationOptions::new(),
        None
    ).expect("could not open calc.exe");

    winapi2::println!("Opened calc.exe.")
}