//! # WinApi2
//!
//! Microsoft Windows user-mode API access with clean Rust types.
//!
//! ## Execution mode
//!
//! Some Windows APIs execute in several layers:
//!
//! - The stable user-mode component
//! - The unstable native component
//! - The system call to the kernel
//!
//! For example, to terminate a process, one typically calls the stable user-mode function
//! `kernel32.TerminateProcess`, which itself calls the unstable native function
//! `ntdll.NtTerminateProcess`, which then performs a system call to `ntoskrnl.NtTerminateProcess`.
//!
//! This crate allows to call every single variant in this chain, but also provides a default
//! option. What the default option uses can be defined with the `winapi` attribute:
//!
//! | Attribute   | Usage              |
//! | ----------- | ------------------ |
//! | Unspecified | Stable user-mode   |
//! | `native`    | Unstable native    |
//! | `syscall`   | Direct system call |
//!
//! The attribute can be specified as an argument to `rustc` via `--cfg winapi="syscall"`, or used
//! by `cargo build` by specifying the following in the `.cargo/config` file at the crate-root:
//!
//! ```toml
//! [target.YOUR_TARGET]
//! rustflags = ['--cfg', 'winapi="syscall"']
//! ```
//!
//! ### Using the `syscall` mode/functions
//!
//! System calls are done by triggering a transition from user- to kernel-mode - the executing
//! thread will end up at a specific function in the Windows kernel. To know which function the user
//! wanted to call, a `0` (`ntoskrnl.exe`) or `0x1000` (`win32k.sys`) based index must be specified
//! in the `eax` register.
//!
//! The crate loads these indices from the `crate::SYSCALL_IDS` variable, which must be set by the
//! crate user prior to any `winapi2` usage:
//!
//! ```ignore
//! fn main() {
//!     unsafe {
//!         winapi2::SYSCALL_IDS = Some(winapi2::SyscallIds {
//!             terminate_process: 0x0001,
//!             // .. set all the system specific system call ids.
//!         });
//!     }
//!
//!     // Now the `syscall` mode and specific `*_syscall` functions can be used.
//!     winapi2::Process::current().terminate_syscall(0);
//! }
//! ```
//!
//! **Warning**: This is architecture specific! It supports 32 bit applications on a 32 bit Windows
//! system, and 64 bit applications on a 64 bit Windows system. Executing a system call in a **32
//! bit application on a 64 bit Windows system** ("WOW64") **will not work** and potentially crash
//! the application if no exception handlers are set up!

#![deny(missing_docs)]
#![feature(asm)]
#![no_std]

// All modules.

pub(crate) mod dll;
pub        mod error;
pub(crate) mod object;
pub        mod process;
pub(crate) mod types;

// Export types.

pub use process::Process;
pub use dll::syscall::{
    Ids as SyscallIds,
    IDS as SYSCALL_IDS
};