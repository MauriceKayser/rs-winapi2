//! Exports by the Windows dynamically loaded library `ntdll.dll`.

#[link(name = "ntdll", kind = "dylib")]
extern "system" {
    /// Official documentation: [ntdll.NtClose](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntclose).
    pub(crate) fn NtClose(
        object: crate::object::Handle
    ) -> Option<crate::error::NtStatus>;

    /// Official documentation: [ntdll.NtOpenProcess](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess).
    pub(crate) fn NtOpenProcess(
        handle: &mut Option<crate::object::Handle>,
        access_modes: crate::process::AccessModes,
        attributes: &crate::object::Attributes,
        client_id: &crate::process::ClientId
    ) -> Option<crate::error::NtStatus>;

    /// Official documentation: [ntdll.NtTerminateProcess](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-zwterminateprocess).
    pub(crate) fn NtTerminateProcess(
        process: crate::object::Handle,
        exit_code: u32
    ) -> Option<crate::error::NtStatus>;
}