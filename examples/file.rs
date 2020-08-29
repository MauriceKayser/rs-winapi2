extern crate alloc;

use winapi2::io::file::*;

fn main() {
    // Must be the done before any syscall related `winapi2` function is called.
    winapi2::SyscallIds::initialize_10_1909();

    winapi2::println!("┌────────────────────┐");
    winapi2::println!("│calc.exe information│");
    winapi2::println!("└────────────────────┘");

    winapi2::print!("1. ");
    calc_architecture();

    winapi2::print!("2. ");
    calc_attributes();

    winapi2::print!("3. ");
    calc_information();
}

fn calc_architecture() {
    let file_path_calc = winapi2::string::String::from(r"\??\C:\Windows\System32\calc.exe");
    let file_path_calc = winapi2::string::StringW::from(file_path_calc.as_ref());
    let object_attributes = winapi2::object::Attributes::from_name(&file_path_calc);

    let file = winapi2::File::create_syscall(
        FileAccessModes::new()
            .set(FileAccessMode::ReadData, true)
            .set_standard(winapi2::object::AccessMode::Synchronize, true),
        &object_attributes,
        None,
        Attributes::new(),
        ShareModes::all(),
        CreationDispositionFileNtDll::OpenExisting,
        CreationOptions::new().set(CreationOption::SynchronousIoNonAlert, true),
        None
    ).expect("could not open calc.exe").0;

    // Read and check the DOS header signature.
    let mut mz = unsafe {
        core::mem::MaybeUninit::<[core::mem::MaybeUninit<u8>; 2]>::uninit().assume_init()
    };
    assert_eq!(
        winapi2::File::read_syscall(&file, None, &mut mz, None),
        Ok([b'M', b'Z'].as_mut())
    );

    // Read the offset to the PE header from the DOS header.
    let mut offset_pe_header = unsafe {
        core::mem::MaybeUninit::<[core::mem::MaybeUninit<u8>; 4]>::uninit().assume_init()
    };
    let offset_pe_header: &u32 = unsafe { winapi2::conversion::cast_mut(winapi2::File::read_syscall(
        &file, None, &mut offset_pe_header, Some(&0x3C)
    ).unwrap()).unwrap() };

    // Read and check the PE header signature.
    let mut pe_header_signature = unsafe {
        core::mem::MaybeUninit::<[core::mem::MaybeUninit<u8>; 4]>::uninit().assume_init()
    };
    assert_eq!(
        winapi2::File::read_syscall(
            &file, None, &mut pe_header_signature, Some(&(*offset_pe_header as u64))
        ),
        Ok([b'P', b'E', 0, 0].as_mut())
    );

    // Read the architecture field in the PE header.
    let mut architecture = unsafe {
        core::mem::MaybeUninit::<[core::mem::MaybeUninit<u8>; 2]>::uninit().assume_init()
    };
    let architecture: &u16 = unsafe { winapi2::conversion::cast_mut(winapi2::File::read_syscall(
        &file, None, &mut architecture, None
    ).unwrap()).unwrap() };

    winapi2::println!("Architecture: {}", match *architecture {
        0x014C => "x86_32",
        0x8664 => "x86_64",
        _ => "Unknown"
    });
}

fn calc_attributes() {
    let file_path_calc = winapi2::string::String::from(r"\??\C:\Windows\System32\calc.exe");
    let file_path_calc = winapi2::string::StringW::from(file_path_calc.as_ref());
    let object_attributes = winapi2::object::Attributes::from_name(&file_path_calc);

    let attributes = Object::attributes_syscall(&object_attributes).unwrap();
    winapi2::println!("Attributes: {}", &attributes);
}

fn calc_information() {
    let file_path_calc = winapi2::string::String::from(r"\??\C:\Windows\System32\calc.exe");
    let file_path_calc = winapi2::string::StringW::from(file_path_calc.as_ref());
    let object_attributes = winapi2::object::Attributes::from_name(&file_path_calc);

    let information = Object::information_syscall(&object_attributes).unwrap();
    winapi2::println!("Basic information: {:?}", &information);
}