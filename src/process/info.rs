//! All process information related Windows types.

/// Official documentation: [PROCESS_BASIC_INFORMATION struct](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess#process_basic_information).
///
/// Unofficial documentation: [PROCESS_BASIC_INFORMATION struct](https://github.com/processhacker/processhacker/blob/master/phnt/include/ntpsapi.h).
#[allow(missing_docs)]
#[repr(C)]
pub struct Basic {
    pub exit_status: Option<crate::error::NtStatus>,
    pub process_environment_block: usize,
    pub affinity_mask: super::thread::CpuAffinityMask,
    base_priority_: isize,
    id_: usize,
    inherited_from_id_: usize
}

impl Basic {
    #[allow(missing_docs)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn base_priority(&self) -> Result<super::thread::PriorityLevel, isize> {
        if self.base_priority_ < core::i32::MIN as isize || self.base_priority_ > core::i32::MAX as isize {
            return Err(self.base_priority_);
        }
        core::convert::TryFrom::try_from(self.base_priority_ as i32).map_err(|_| self.base_priority_)
    }

    #[allow(missing_docs)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub const fn id(&self) -> u32 {
        self.id_ as u32
    }

    #[allow(missing_docs)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub const fn inherited_from_id(&self) -> u32 {
        self.inherited_from_id_ as u32
    }
}

impl core::fmt::Debug for Basic {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct(stringify!(Basic))
            .field(stringify!(exit_status), &self.exit_status)
            .field(stringify!(process_environment_block), &self.process_environment_block)
            .field(stringify!(affinity_mask), &self.affinity_mask)
            .field(stringify!(base_priority), &self.base_priority())
            .field(stringify!(id), &self.id())
            .field(stringify!(inherited_from_id), &self.inherited_from_id())
            .finish()
    }
}