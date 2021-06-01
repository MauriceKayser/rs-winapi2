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
        let buffer = unsafe { crate::dll::kernel32::GetCommandLineW() };

        (buffer as usize != 0).then(|| Self { buffer })
    }

    /// Returns an iterator over the arguments in the command line string.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn iter(
        &self,
        exclude_zero_terminator: bool
    ) -> Result<CommandLineIterator, crate::error::Status> {
        CommandLineIterator::new(self, exclude_zero_terminator)
    }
}

/// An iterator over the arguments in the command line string.
pub struct CommandLineIterator<'a> {
    buffer: &'a [*const WideChar],
    index: usize,
    exclude_zero_terminator: bool
}

impl<'a> CommandLineIterator<'a> {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn new(
        command_line: &CommandLine,
        exclude_zero_terminator: bool
    ) -> Result<Self, crate::error::Status> {
        unsafe {
            let mut count = core::mem::MaybeUninit::uninit();
            let arguments = crate::dll::shell32::CommandLineToArgvW(
                command_line.buffer, count.as_mut_ptr()
            );
            if arguments as usize == 0 || count.assume_init() < 0 {
                return Err(crate::error::Status::last().unwrap());
            }

            Ok(Self {
                buffer: core::slice::from_raw_parts(arguments, count.assume_init() as usize),
                index: 0,
                exclude_zero_terminator
            })
        }
    }
}

impl<'a> core::ops::Drop for CommandLineIterator<'a> {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn drop(&mut self) {
        let handle = unsafe {
            crate::dll::kernel32::LocalFree(self.buffer.as_ptr() as _)
        };
        debug_assert_eq!(handle as usize, 0);
    }
}

impl<'a> core::iter::Iterator for CommandLineIterator<'a> {
    type Item = &'a crate::string::Str;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn next(&mut self) -> Option<Self::Item> {
        let parameter_ptr = self.buffer.get(self.index)?.clone();
        self.index += 1;

        Some(unsafe { crate::string::Str::from_terminated(
            parameter_ptr, self.exclude_zero_terminator
        ) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec::Vec};

    // Test code.

    #[test]
    fn iterator_all() {
        // An empty input string results in the full program path.
        let command_line = CommandLine { buffer: [0].as_ptr() };
        let arguments: Vec<&crate::string::Str> =
            command_line.iter(true).unwrap().collect();

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

            let command_line = CommandLine { buffer: input_terminated.as_ptr() };
            let arguments: Vec<&crate::string::Str> =
                command_line.iter(true).unwrap().collect();
            let arguments_terminated: Vec<&crate::string::Str> =
                command_line.iter(false).unwrap().collect();

            assert_eq!(&arguments.as_slice(), expected);
            assert_eq!(arguments_terminated, expected_terminated);
        }
    }
}