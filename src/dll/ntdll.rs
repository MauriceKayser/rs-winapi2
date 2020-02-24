//! Exports by the Windows dynamically loaded library `ntdll.dll`.

#[link(name = "ntdll", kind = "dylib")]
extern "system" {
    /// Official documentation: [ntdll.NtClose](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntclose).
    pub(crate) fn NtClose(
        object: crate::object::Handle
    ) -> crate::error::NtStatus;

    /// Official documentation: [ntdll.NtTerminateProcess](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-zwterminateprocess).
    pub(crate) fn NtTerminateProcess(
        process: crate::object::Handle,
        exit_code: u32
    ) -> crate::error::NtStatus;
}