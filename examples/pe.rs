extern crate alloc;

fn main() {
    let ldr_entry =
        unsafe { winapi2::process::EnvironmentBlock::current_from_block_teb() }.unwrap()
            .loader_data.as_ref().unwrap()
            // Current process image
            .load_order_next.as_ref().unwrap()
            // ntdll.dll
            .load_order_next.as_ref().unwrap()
            // kernel32.dll
            .load_order_next.as_ref().unwrap();

    let mut parser = ldr_entry.image_base_address.unwrap().create_parser(
        ldr_entry.image_virtual_size, winapi2::pe::ParsingMode::Virtual
    ).unwrap();

    winapi2::print!("Exports for ");
    winapi2::print_wide!(ldr_entry.image_name.as_ref());
    winapi2::println!(":");
    for export in parser.exports(true).unwrap() {
        winapi2::print!("- ({}): {} ", export.ordinal, export.name);
        match export.data {
            winapi2::pe::export::Data::InModule(buffer) => winapi2::println!("in module at 0x{:X}", buffer.as_ptr() as usize),
            winapi2::pe::export::Data::OutOfModule(address) => winapi2::println!("out of module at 0x{:X}", address as usize),
            winapi2::pe::export::Data::Forwarded(forwarder) => winapi2::println!("forwards to: {}", forwarder.into_lossy())
        }
    }
}