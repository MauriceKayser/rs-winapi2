//! All process information related Windows types.

/// Official documentation: [PROCESS_BASIC_INFORMATION struct](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess#process_basic_information).
#[allow(missing_docs)]
#[repr(C)]
pub struct Basic {
    pub exit_status: Option<crate::error::NtStatus>,
    pub process_environment_block: usize,
    affinity_mask: usize,
    base_priority: usize,
    id: usize,
    inherited_from_id: usize
}

impl Basic {
    #[allow(missing_docs)]
    pub const fn id(&self) -> u32 {
        self.id as u32
    }

    #[allow(missing_docs)]
    pub const fn inherited_from_id(&self) -> u32 {
        self.inherited_from_id as u32
    }
}