//! All system information related Windows types.

/// Official documentation: [SYSTEM_PROCESS_INFORMATION struct](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/66ef46a7-504f-4696-9613-0bd8446ee225).
///
/// Unofficial documentation: [SYSTEM_PROCESS_INFORMATION struct](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/process.htm).
#[allow(missing_docs)]
#[repr(C)]
pub struct Process<'a> {
    pub(crate) next_offset: Option<core::num::NonZeroU32>,
    pub(crate) thread_count: u32,
    pub working_set_private_size: i64,
    pub hard_fault_count: u32,
    pub thread_count_high: u32,
    pub cycle_time: u64,
    pub create_time: crate::io::file::Time,
    pub user_time: i64,
    pub kernel_time: i64,
    pub image_name: crate::string::StringW<'a>,
    base_priority_: i32,
    pub id: Option<crate::process::Id>,
    pub inherited_from_id: Option<crate::process::Id>,
    pub handle_count: u32,
    pub session_id: u32,
    pub key: usize,
    pub virtual_size_peak: usize,
    pub virtual_size: usize,
    pub page_fault_count: u32,
    pub working_set_size_peak: usize,
    pub working_set_size: usize,
    pub paged_pool_quota_size_peak: usize,
    pub paged_pool_quota_size: usize,
    pub non_paged_pool_quota_size_peak: usize,
    pub non_paged_pool_quota_size: usize,
    pub page_file_size: usize,
    pub page_file_size_peak: usize,
    pub private_page_size: usize,
    pub operation_read_count: i64,
    pub operation_write_count: i64,
    pub operation_other_count: i64,
    pub transfer_read_count: i64,
    pub transfer_write_count: i64,
    pub transfer_other_count: i64
}

impl<'a> Process<'a> {
    #[allow(missing_docs)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn base_priority(&self) -> Result<crate::process::thread::PriorityLevel, i32> {
        TryFrom::try_from(self.base_priority_)
    }
}

impl<'a> core::fmt::Debug for Process<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct(stringify!(InformationProcess))
            .field(stringify!(working_set_private_size), &self.working_set_private_size)
            .field(stringify!(hard_fault_count), &self.hard_fault_count)
            .field(stringify!(thread_count_high), &self.thread_count_high)
            .field(stringify!(cycle_time), &self.cycle_time)
            .field(stringify!(create_time), &self.create_time)
            .field(stringify!(user_time), &self.user_time)
            .field(stringify!(kernel_time), &self.kernel_time)
            .field(stringify!(image_name), &self.image_name.as_ref())
            .field(stringify!(base_priority), &self.base_priority())
            .field(stringify!(id), &self.id)
            .field(stringify!(inherited_from_id), &self.inherited_from_id)
            .field(stringify!(handle_count), &self.handle_count)
            .field(stringify!(session_id), &self.session_id)
            .field(stringify!(key), &self.key)
            .field(stringify!(virtual_size_peak), &self.virtual_size_peak)
            .field(stringify!(virtual_size), &self.virtual_size)
            .field(stringify!(page_fault_count), &self.page_fault_count)
            .field(stringify!(working_set_size_peak), &self.working_set_size_peak)
            .field(stringify!(working_set_size), &self.working_set_size)
            .field(stringify!(paged_pool_quota_size_peak), &self.paged_pool_quota_size_peak)
            .field(stringify!(paged_pool_quota_size), &self.paged_pool_quota_size)
            .field(stringify!(non_paged_pool_quota_size_peak), &self.non_paged_pool_quota_size_peak)
            .field(stringify!(non_paged_pool_quota_size), &self.non_paged_pool_quota_size)
            .field(stringify!(page_file_size), &self.page_file_size)
            .field(stringify!(page_file_size_peak), &self.page_file_size_peak)
            .field(stringify!(private_page_size), &self.private_page_size)
            .field(stringify!(operation_read_count), &self.operation_read_count)
            .field(stringify!(operation_write_count), &self.operation_write_count)
            .field(stringify!(operation_other_count), &self.operation_other_count)
            .field(stringify!(transfer_read_count), &self.transfer_read_count)
            .field(stringify!(transfer_write_count), &self.transfer_write_count)
            .field(stringify!(transfer_other_count), &self.transfer_other_count)
            .finish()
    }
}

/// Official documentation: [SYSTEM_THREAD_INFORMATION struct](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/e82d73e4-cedb-4077-9099-d58f3459722f).
#[allow(missing_docs)]
#[repr(C)]
pub struct Thread {
    pub kernel_time: i64,
    pub user_time: i64,
    pub create_time: crate::io::file::Time,
    pub wait_time: u32,
    pub start_address: usize,
    pub id: crate::process::ClientId,
    priority_: i32,
    base_priority_: i32,
    pub context_switches: u32,
    state_: u32,
    wait_reason_: u32
}

impl Thread {
    #[allow(missing_docs)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn base_priority(&self) -> Result<crate::process::thread::PriorityLevel, i32> {
        TryFrom::try_from(self.base_priority_)
    }

    #[allow(missing_docs)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn priority(&self) -> Result<crate::process::thread::PriorityLevel, i32> {
        TryFrom::try_from(self.priority_)
    }

    #[allow(missing_docs)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn state(&self) -> Result<crate::process::thread::State, u32> {
        TryFrom::try_from(self.state_)
    }

    #[allow(missing_docs)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn wait_reason(&self) -> Result<crate::process::thread::WaitReason, u32> {
        TryFrom::try_from(self.wait_reason_)
    }
}

impl core::fmt::Debug for Thread {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct(stringify!(InformationThread))
            .field(stringify!(kernel_time), &self.kernel_time)
            .field(stringify!(user_time), &self.user_time)
            .field(stringify!(create_time), &self.create_time)
            .field(stringify!(wait_time), &self.wait_time)
            .field(stringify!(start_address), &self.start_address)
            .field(stringify!(id), &self.id)
            .field(stringify!(priority), &self.priority())
            .field(stringify!(base_priority), &self.base_priority())
            .field(stringify!(context_switches), &self.context_switches)
            .field(stringify!(state), &self.state())
            .field(stringify!(wait_reason), &self.wait_reason())
            .finish()
    }
}