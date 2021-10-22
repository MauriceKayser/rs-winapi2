#![feature(alloc_error_handler)]
#![no_main]
#![no_std]

extern crate alloc;
#[macro_use]
extern crate winapi2;

mod bootstrap;

#[inline(never)]
fn main() -> u32 {
    println!("Hello world!");

    0
}