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
    pub id: Option<super::Id>,
    pub inherited_from_id: Option<super::Id>
}

impl Basic {
    #[allow(missing_docs)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn base_priority(&self) -> Result<super::thread::PriorityLevel, isize> {
        if self.base_priority_ < i32::MIN as isize || self.base_priority_ > i32::MAX as isize {
            return Err(self.base_priority_);
        }
        TryFrom::try_from(self.base_priority_ as i32).map_err(|_| self.base_priority_)
    }
}

impl core::fmt::Debug for Basic {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct(stringify!(Basic))
            .field(stringify!(exit_status), &self.exit_status)
            .field(stringify!(process_environment_block), &self.process_environment_block)
            .field(stringify!(affinity_mask), &self.affinity_mask)
            .field(stringify!(base_priority), &self.base_priority())
            .field(stringify!(id), &self.id)
            .field(stringify!(inherited_from_id), &self.inherited_from_id)
            .finish()
    }
}