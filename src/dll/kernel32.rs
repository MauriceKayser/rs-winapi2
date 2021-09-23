//! Exports by the Windows dynamically loaded library `kernel32.dll`.

#[link(name = "kernel32", kind = "dylib")]
extern "system" {
    /// Official documentation: [kernel32.CloseHandle](https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle).
    #[cfg(not(any(winapi = "native", winapi = "syscall")))]
    pub(crate) fn CloseHandle(
        object: crate::object::Handle
    ) -> crate::types::Boolean;

    /// Official documentation: [kernel32.CreateDirectoryW](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createdirectoryw).
    pub(crate) fn CreateDirectoryW(
        path: *const crate::string::WideChar,
        security_descriptor: Option<&crate::object::security::Descriptor>
    ) -> crate::types::Boolean;

    /// Official documentation: [kernel32.CreateFileW](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).
    pub(crate) fn CreateFileW(
        path: *const crate::string::WideChar,
        // Specializations:
        // - `crate::file::DirectoryAccessModes`
        // - `crate::file::FileAccessModes`
        access_modes: u32,
        share_modes: crate::io::file::ShareModes,
        security_descriptor: Option<&crate::object::security::Descriptor>,
        // Specializations:
        // - `crate::file::CreationDispositionDirectoryKernel32`
        // - `crate::file::CreationDispositionFileKernel32`
        creation_disposition: u32,
        attributes: crate::io::file::Attributes,
        template: Option<crate::object::Handle>
    ) -> crate::object::Handle;

    /// https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-freelibrary
    pub(crate) fn FreeLibrary(
        module: crate::process::Module
    ) -> crate::types::Boolean;

    /// Official documentation: [kernel32.GetCommandLineW](https://docs.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getcommandlinew).
    pub(crate) fn GetCommandLineW() -> *const crate::string::WideChar;

    /// Official documentation: [kernel32.GetConsoleMode](https://docs.microsoft.com/en-us/windows/console/getconsolemode).
    pub(crate) fn GetConsoleMode(
        handle: crate::object::Handle,
        // Flags, specific to `handle` being an in- or output handle.
        modes: *mut u32
    ) -> crate::types::Boolean;

    /// Official documentation: [kernel32.GetFileAttributesExW](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileattributesexw).
    pub(crate) fn GetFileAttributesExW(
        path: *const crate::string::WideChar,
        level: crate::io::file::AttributeInfoLevel,
        buffer: *mut u8
    ) -> crate::types::Boolean;

    /// Official documentation: [kernel32.GetLastError](https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror).
    pub(crate) fn GetLastError() -> Option<crate::error::Status>;

    /// Official documentation: [kernel32.GetProcessHeap](https://docs.microsoft.com/en-us/windows/desktop/api/heapapi/nf-heapapi-getprocessheap).
    pub(crate) fn GetProcessHeap() -> Option<crate::heap::SystemHeapHandle>;

    /// Official documentation: [kernel32.GetStdHandle](https://docs.microsoft.com/en-us/windows/console/getstdhandle).
    pub(crate) fn GetStdHandle(
        standard_device: crate::console::StandardDevice
    ) -> crate::object::Handle;

    /// Official documentation: [kernel32.HeapAlloc](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc).
    pub(crate) fn HeapAlloc(
        heap: crate::heap::SystemHeapHandle,
        flags: crate::heap::SystemHeapFlags,
        size: usize
    ) -> *mut u8;

    /// Official documentation: [kernel32.HeapFree](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapfree).
    pub(crate) fn HeapFree(
        heap: crate::heap::SystemHeapHandle,
        flags: crate::heap::SystemHeapFlags,
        buffer: *mut u8
    ) -> crate::types::Boolean;

    /// https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw
    pub(crate) fn LoadLibraryExW(
        path: *const crate::string::WideChar,
        _: usize,
        flags: crate::process::LoadModuleFlags
    ) -> Option<crate::process::Module>;

    /// Official documentation: [kernel32.LocalFree](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-localfree).
    pub(crate) fn LocalFree(
        buffer: *mut u8
    ) -> *mut u8;

    /// Official documentation: [kernel32.OpenProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess).
    pub(crate) fn OpenProcess(
        access_modes: crate::process::AccessModes,
        inherit_handles: crate::types::Boolean,
        id: u32
    ) -> Option<crate::object::Handle>;

    /// Official documentation: [kernel32.ReadFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile).
    pub(crate) fn ReadFile(
        file: crate::object::Handle,
        buffer: *mut u8,
        buffer_size: u32,
        read_size: *mut u32,
        overlapped: Option<&mut crate::io::Overlapped>
    ) -> crate::types::Boolean;

    /// Official documentation: [kernel32.TerminateProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess).
    pub(crate) fn TerminateProcess(
        process: crate::object::Handle,
        exit_code: u32
    ) -> crate::types::Boolean;

    /// Official documentation: [kernel32.VirtualQueryEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex).
    pub(crate) fn VirtualQueryEx(
        process: crate::object::Handle,
        address: usize,
        // crate::process::memory::info::Basic<T>
        buffer: *mut u8,
        buffer_size: usize
    ) -> usize;

    /// Official documentation: [kernel32.WriteConsoleW](https://docs.microsoft.com/en-us/windows/console/writeconsole).
    pub(crate) fn WriteConsoleW(
        output_handle: crate::object::Handle,
        buffer: *const crate::string::WideChar,
        buffer_size: u32,
        written_size: *mut u32,
        _reserved: *const u8
    ) -> crate::types::Boolean;

    /// Official documentation: [kernel32.WriteFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile).
    pub(crate) fn WriteFile(
        file: crate::object::Handle,
        buffer: *const u8,
        buffer_size: u32,
        written_size: *mut u32,
        overlapped: Option<&mut crate::io::Overlapped>
    ) -> crate::types::Boolean;
}