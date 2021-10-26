//! Exports by the Windows dynamically loaded library `shell32.dll`.

#[link(name = "shell32", kind = "dylib")]
extern "system" {
    /// Official documentation: [shell32.CommandLineToArgvW](https://docs.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-commandlinetoargvw).
    pub(crate) fn CommandLineToArgvW(
        command_line: *const crate::string::WideChar,
        arguments: *mut i32
    ) -> *const *mut crate::string::WideChar;
}