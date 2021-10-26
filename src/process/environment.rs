//! All process environment related Windows types.

use crate::string::WideChar;

/// Allows querying the command line string of a process.
pub struct CommandLine {
    buffer: *const WideChar
}

impl CommandLine {
    /// Retrieves the command line arguments of the current process.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn get() -> Option<Self> {
        #[cfg(not(any(winapi = "native", winapi = "syscall")))]
        { Self::get_kernel32() }
        #[cfg(any(winapi = "native", winapi = "syscall"))]
        unsafe { Self::get_native() }
    }

    /// Retrieves the command line arguments of the current process.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn get_kernel32() -> Option<Self> {
        let buffer = unsafe { crate::dll::kernel32::GetCommandLineW() };

        (buffer as usize != 0).then(|| Self { buffer })
    }

    /// Retrieves the command line arguments of the current process.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub unsafe fn get_native() -> Option<Self> {
        crate::process::EnvironmentBlock::current_from_block_teb()
            .and_then(|peb| peb.parameters.as_deref())
            .and_then(|parameters| Some(Self { buffer: parameters.command_line.buffer }))
    }

    /// Returns a split variant of the command line string.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn split<'a>(&self) -> Result<CommandLineSplit<'a>, crate::error::Status> {
        unsafe {
            let mut count = core::mem::MaybeUninit::uninit();
            let arguments = crate::dll::shell32::CommandLineToArgvW(
                self.buffer, count.as_mut_ptr()
            );
            if arguments as usize == 0 || count.assume_init() < 0 {
                return Err(crate::error::Status::last().unwrap());
            }

            Ok(CommandLineSplit { buffer: core::slice::from_raw_parts(
                arguments, count.assume_init() as usize
            ) })
        }
    }
}

/// An iterator over the arguments in the command line string.
pub struct CommandLineIterator<'a> {
    split: &'a CommandLineSplit<'a>,
    index: usize,
    exclude_zero_terminator: bool
}

impl<'a> core::iter::Iterator for CommandLineIterator<'a> {
    type Item = &'a crate::string::Str;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn next(&mut self) -> Option<Self::Item> {
        let parameter_ptr = self.split.buffer.get(self.index)?.clone();
        self.index += 1;

        Some(unsafe { crate::string::Str::from_terminated(
            parameter_ptr, None, self.exclude_zero_terminator
        ) })
    }
}

/// Stores the split command line buffers.
pub struct CommandLineSplit<'a> {
    buffer: &'a [*const WideChar]
}

impl<'a> CommandLineSplit<'a> {
    /// Returns an iterator over the arguments in the command line string.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub const fn iter(&'a self, exclude_zero_terminator: bool) -> CommandLineIterator<'a> {
        CommandLineIterator { split: self, index: 0, exclude_zero_terminator }
    }

    /// Returns the amount of arguments in the command line string.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub const fn len(&self) -> usize {
        self.buffer.len()
    }
}

impl<'a> core::ops::Drop for CommandLineSplit<'a> {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn drop(&mut self) {
        let handle = unsafe {
            crate::dll::kernel32::LocalFree(self.buffer.as_ptr() as _)
        };
        debug_assert_eq!(handle as usize, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec::Vec};

    // Test code.

    #[test]
    fn command_line_get() {
        let kernel32 = CommandLine::get_kernel32().unwrap();
        let native = unsafe { CommandLine::get_native().unwrap() };

        assert_eq!(kernel32.buffer, native.buffer);
    }

    #[test]
    fn command_line_iterator() {
        // An empty input string results in the full program path.
        let command_line = CommandLine { buffer: [0].as_ptr() }.split().unwrap();
        let arguments: Vec<&crate::string::Str> = command_line.iter(true).collect();

        assert_eq!(arguments.len(), 1);
        let argument = ToString::to_string(arguments.first().unwrap());
        assert!(argument.contains("winapi2"));
        assert!(argument.ends_with(".exe"));

        // Non-empty test data.
        const TEST_DATA: &[(&str, &[&str])] = &[
            (" ", &[""]),
            ("  ", &[""]),
            ("a", &["a"]),
            ("a b", &["a", "b"]),
            (" a", &["", "a"]),
            ("  a", &["", "a"]),
            (r#""a""#, &["a"]),
            (r#""a b""#, &["a b"]),
            (r#"" a""#, &[" a"]),
            (r#""a"#, &["a"]),
            (r#"" a"#, &[" a"]),
            (r#"a"b"#, &[r#"a"b"#]),
            (r#"a""b"#, &[r#"a""b"#]),
            (r#"a"""b"#, &[r#"a"""b"#]),
            (r#"a"b"c"#, &[r#"a"b"c"#]),
            (r#""a""b"#, &["a", "b"]),
            (r#"a""b""#, &[r#"a""b""#]),
            (r#""a""b""#, &["a", "b"]),
            (r#"\"#, &[r#"\"#]),
            (r#"\\"#, &[r#"\\"#]),
            (r#"\n"#, &[r#"\n"#]),
            (r#"\\n"#, &[r#"\\n"#]),
            (r#"\"a b"#, &[r#"\"a"#, "b"]),
            (r#"\"a b""#, &[r#"\"a"#, "b"]),
            (r#"\\"a b"#, &[r#"\\"a"#, "b"]),
            (r#"\\"a b""#, &[r#"\\"a"#, "b"])
        ];

        let mut input_terminated = crate::string::String::new();
        for (input, expected) in TEST_DATA {
            alloc::string::String::new().clear();
            input_terminated.clear();
            input_terminated.push_utf8(input);
            input_terminated.push(0);

            let expected_terminated: Vec<crate::string::String> = expected.iter().map(|str| {
                let mut expected_terminated = crate::string::String::new();
                expected_terminated.push_utf8(str);
                expected_terminated.push(0);
                expected_terminated
            }).collect();
            let expected_terminated: Vec<&crate::string::Str> = expected_terminated.iter()
                .map(|s| s.as_ref()).collect();

            let command_line = CommandLine { buffer: input_terminated.as_ptr() }.split().unwrap();
            let arguments: Vec<&crate::string::Str> =
                command_line.iter(true).collect();
            let arguments_terminated: Vec<&crate::string::Str> =
                command_line.iter(false).collect();

            assert_eq!(&arguments.as_slice(), expected);
            assert_eq!(arguments_terminated, expected_terminated);
        }
    }
}