//! All console related Windows types.

/// Provides static methods to interact with the current console.
pub struct Console();

impl Console {
    /// Writes UTF-8 encoded text to the console.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn write(text: &str) -> crate::error::ErrorResult {
        Self::write_kernel32(text).map(|s| crate::error::Error::Status(s))
        // TODO: ntdll & syscall.
    }

    /// Writes wide char encoded text to the console.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn write_wide(text: &crate::string::Str) -> crate::error::ErrorResult {
        Self::write_wide_kernel32(text).map(|s| crate::error::Error::Status(s))
        // TODO: ntdll & syscall.
    }

    /// Writes UTF-8 encoded text to the error console.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn write_error(text: &str) -> crate::error::ErrorResult {
        Self::write_error_kernel32(text).map(|s| crate::error::Error::Status(s))
        // TODO: ntdll & syscall.
    }

    /// Writes wide char encoded text to the error console.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn write_error_wide(text: &crate::string::Str) -> crate::error::ErrorResult {
        Self::write_error_wide_kernel32(text).map(|s| crate::error::Error::Status(s))
        // TODO: ntdll & syscall.
    }

    /// Writes UTF-8 encoded text to the console.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn write_kernel32(text: &str) -> crate::error::StatusResult {
        Self::internal_write_kernel32(text, StandardDevice::Output)
    }

    /// Writes wide char encoded text to the console.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn write_wide_kernel32(text: &crate::string::Str) -> crate::error::StatusResult {
        Self::internal_write_wide_kernel32(text, StandardDevice::Output)
    }

    /// Writes UTF-8 encoded text to the error console.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn write_error_kernel32(text: &str) -> crate::error::StatusResult {
        Self::internal_write_kernel32(text, StandardDevice::Error)
    }

    /// Writes wide char encoded text to the error console.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn write_error_wide_kernel32(text: &crate::string::Str) -> crate::error::StatusResult {
        Self::internal_write_wide_kernel32(text, StandardDevice::Error)
    }

    /// In case of the output being directed to the console, the text is converted to UTF-16.
    /// In case of the output being redirected to a file, the text is written in UTF-8.
    fn internal_write_kernel32(text: &str, standard_device: StandardDevice)
        -> crate::error::StatusResult
    {
        unsafe {
            let output = crate::dll::kernel32::GetStdHandle(standard_device);

            if !output.is_pseudo() {
                let mut _mode = core::mem::MaybeUninit::uninit();
                let mut written_size = core::mem::MaybeUninit::uninit();

                if crate::dll::kernel32::GetConsoleMode(
                    output.clone(), _mode.as_mut_ptr()
                ).as_bool() {
                    let converted = crate::string::String::from(text);

                    if crate::dll::kernel32::WriteConsoleW(
                        output,
                        converted.as_ptr(),
                        core::cmp::min(converted.len(), core::u32::MAX as usize) as u32,
                        written_size.as_mut_ptr(),
                        0 as *const _
                    ).as_bool() && written_size.assume_init() as usize == converted.len() {
                        return None;
                    }
                } else {
                    if crate::dll::kernel32::WriteFile(
                        output,
                        text.as_ptr(),
                        core::cmp::min(text.len(), core::u32::MAX as usize) as u32,
                        written_size.as_mut_ptr(),
                        None
                    ).as_bool() && written_size.assume_init() as usize == text.len() {
                        return None;
                    }
                }
            }

            Some(crate::error::Status::last().unwrap())
        }
    }

    /// In case of the output being directed to the console, the text is written in UTF-16.
    /// In case of the output being redirected to a file, the text is converted to UTF-8.
    fn internal_write_wide_kernel32(text: &crate::string::Str, standard_device: StandardDevice)
        -> crate::error::StatusResult
    {
        unsafe {
            let output = crate::dll::kernel32::GetStdHandle(standard_device);

            if !output.is_pseudo() {
                let mut _mode = core::mem::MaybeUninit::uninit();
                let mut written_size = core::mem::MaybeUninit::uninit();

                if crate::dll::kernel32::GetConsoleMode(
                    output.clone(), _mode.as_mut_ptr()
                ).as_bool() {
                    if crate::dll::kernel32::WriteConsoleW(
                        output,
                        text.as_ptr(),
                        core::cmp::min(text.len(), core::u32::MAX as usize) as u32,
                        written_size.as_mut_ptr(),
                        0 as *const _
                    ).as_bool() && written_size.assume_init() as usize == text.len() {
                        return None;
                    }
                } else {
                    let converted = text.into_lossy();

                    if crate::dll::kernel32::WriteFile(
                        output,
                        converted.as_ptr(),
                        core::cmp::min(converted.len(), core::u32::MAX as usize) as u32,
                        written_size.as_mut_ptr(),
                        None
                    ).as_bool() && written_size.assume_init() as usize == converted.len() {
                        return None;
                    }
                }
            }

            Some(crate::error::Status::last().unwrap())
        }
    }
}

/// Official documentation: [Standard Console Device](https://docs.microsoft.com/en-us/windows/console/getstdhandle).
#[repr(i32)]
pub(crate) enum StandardDevice {
    Error = -12,
    Output,
    #[allow(unused)]
    Input
}

/// Prints to the standard output.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ({let _ = $crate::console::Console::write(&alloc::format!($($arg)*));});
}

/// Prints to the standard error.
#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => ({let _ = $crate::console::Console::write_error(&alloc::format!($($arg)*));});
}

/// Prints to the standard output.
#[macro_export]
macro_rules! print_wide {
    ($wstr:expr) => ({let _ = $crate::console::Console::write_wide($wstr);});
}

/// Prints to the standard error.
#[macro_export]
macro_rules! eprint_wide {
    ($wstr:expr) => ({let _ = $crate::console::Console::write_error_wide($wstr);});
}

/// Prints to the standard output, with an appended new-line character.
#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", alloc::format!($($arg)*)););
}

/// Prints to the standard error, with an appended new-line character.
#[macro_export]
macro_rules! eprintln {
    () => ($crate::eprint!("\n"));
    ($($arg:tt)*) => ($crate::eprint!("{}\n", alloc::format!($($arg)*)););
}

/// Prints to the standard output, with an appended new-line character.
#[macro_export]
macro_rules! println_wide {
    () => ($crate::print!("\n"));
    ($wstr:expr) => ($crate::print_wide!($wstr); $crate::println_wide!(););
}

/// Prints to the standard error, with an appended new-line character.
#[macro_export]
macro_rules! eprintln_wide {
    () => ($crate::eprint!("\n"));
    ($wstr:expr) => ($crate::eprint_wide!($wstr); $crate::eprintln_wide!(););
}