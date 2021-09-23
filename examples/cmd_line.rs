extern crate alloc;

fn main() {
    let cmd_line = winapi2::process::environment::CommandLine::get().unwrap()
        .split().unwrap();

    for (i, entry) in cmd_line.iter(true).enumerate() {
        winapi2::println!("{:2}. {}", i, entry);
    }
}