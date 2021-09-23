//! All process memory information related Windows types.

/// Official documentation: [MEMORY_BASIC_INFORMATION struct](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information).
#[allow(missing_docs)]
#[cfg_attr(debug_assertions, derive(Eq, PartialEq))]
#[derive(Debug)]
#[repr(C)]
pub struct Basic {
    pub base_address: usize,
    pub allocation_base: usize,
    pub allocation_protection: super::Protection,
    pub region_size: usize,
    /// Can be one of: `Commit`, `Reserve`, or `Free`.
    pub states: super::States,
    pub protection: super::Protection,
    /// Can be one of: `Private`, `Mapped`, or `Image`, or none if `states` is `Free`.
    pub kinds: super::Kinds
}

impl crate::Process {
    /// Official documentation: [kernel32.VirtualQueryEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex).
    ///
    /// Official documentation: [ntdll.NtQueryVirtualMemory](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvirtualmemory).
    ///
    /// Returns basic information about the specified process memory.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn memory_information(&self, address: usize) -> Result<Basic, crate::error::Error> {
        {
            #[cfg(not(any(winapi = "native", winapi = "syscall")))]
            { self.memory_information_kernel32(address) }
            #[cfg(winapi = "native")]
            { self.memory_information_ntdll(address) }
            #[cfg(winapi = "syscall")]
            { self.memory_information_syscall(address) }
        }.map_err(|e| e.into())
    }

    /// Official documentation: [kernel32.VirtualQueryEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex).
    ///
    /// Official documentation: [ntdll.NtQueryVirtualMemory](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvirtualmemory).
    ///
    /// Returns basic information about the specified process memory.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn memory_information_kernel32(&self, address: usize)
        -> Result<Basic, crate::error::Status>
    {
        const BUFFER_SIZE: usize = core::mem::size_of::<Basic>();

        let mut buffer = core::mem::MaybeUninit::<Basic>::uninit();

        unsafe {
            match crate::dll::kernel32::VirtualQueryEx(
                self.0.clone(),
                address,
                buffer.as_mut_ptr() as _,
                BUFFER_SIZE
            ) {
                BUFFER_SIZE => Ok(buffer.assume_init()),
                0 => Err(crate::error::Status::last().unwrap_unchecked()),
                _ => Err(crate::error::StatusValue::BadLength.into())
            }
        }
    }

    /// Official documentation: [kernel32.VirtualQueryEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex).
    ///
    /// Official documentation: [ntdll.NtQueryVirtualMemory](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvirtualmemory).
    ///
    /// Returns basic information about the specified process memory.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn memory_information_ntdll(&self, address: usize)
        -> Result<Basic, crate::error::NtStatus>
    {
        const BUFFER_SIZE: usize = core::mem::size_of::<Basic>();

        let mut buffer = core::mem::MaybeUninit::<Basic>::uninit();
        let mut written_size = core::mem::MaybeUninit::uninit();

        unsafe {
            if let Some(status) = crate::dll::ntdll::NtQueryVirtualMemory(
                self.0.clone(),
                address,
                super::Information::Basic,
                buffer.as_mut_ptr() as _,
                BUFFER_SIZE,
                written_size.as_mut_ptr()
            ) { return Err(status); }

            match written_size.assume_init() {
                BUFFER_SIZE => Ok(buffer.assume_init()),
                _ => Err(crate::error::NtStatusValue::InfoLengthMismatch.into())
            }
        }
    }

    /// Official documentation: [kernel32.VirtualQueryEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex).
    ///
    /// Official documentation: [ntdll.NtQueryVirtualMemory](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvirtualmemory).
    ///
    /// Returns basic information about the specified process memory.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn memory_information_syscall(&self, address: usize)
        -> Result<Basic, crate::error::NtStatus>
    {
        const BUFFER_SIZE: usize = core::mem::size_of::<Basic>();

        let mut buffer = core::mem::MaybeUninit::<Basic>::uninit();
        let mut written_size = core::mem::MaybeUninit::uninit();

        unsafe {
            if let Some(status) = crate::dll::syscall::NtQueryVirtualMemory(
                self.0.clone(),
                address,
                super::Information::Basic,
                buffer.as_mut_ptr() as _,
                BUFFER_SIZE,
                written_size.as_mut_ptr()
            ) { return Err(status); }

            match written_size.assume_init() {
                BUFFER_SIZE => Ok(buffer.assume_init()),
                _ => Err(crate::error::NtStatusValue::InfoLengthMismatch.into())
            }
        }
    }
}

/// An iterator over basic information about process memory.
///
/// Using this type on a process which is not suspended can lead to unexpected results.
pub struct BasicIterator<'a, E> {
    process: &'a crate::Process,
    address: usize,
    func: fn(&crate::Process, usize) -> Result<Basic, E>,
    is_done: bool
}

impl<'a, E> core::iter::Iterator for BasicIterator<'a, E> {
    type Item = Basic;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn next(&mut self) -> Option<Self::Item> {
        if self.is_done {
            return None;
        }

        match (self.func)(self.process, self.address) {
            Ok(result) => {
                // Calculate the next address to query.
                if let Some(address) = result.base_address.checked_add(result.region_size) {
                    self.address = address;
                    return Some(result);
                }

                self.is_done = true;
                Some(result)
            },

            Err(_) => {
                self.is_done = true;
                None
            }
        }
    }
}

impl crate::Process {
    /// Official documentation: [kernel32.VirtualQueryEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex).
    ///
    /// Official documentation: [ntdll.NtQueryVirtualMemory](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvirtualmemory).
    ///
    /// Returns an iterator over basic information about the process memory.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn iter_memory_information(&self, start_address: usize)
        -> BasicIterator<crate::error::Error>
    {
        BasicIterator {
            process: self,
            address: start_address,
            func: {
                #[cfg(not(any(winapi = "native", winapi = "syscall")))]
                { |p, a| crate::Process::memory_information_kernel32(p, a).map_err(|e| e.into()) }
                #[cfg(winapi = "native")]
                { |p, a| crate::Process::memory_information_ntdll(p, a).map_err(|e| e.into()) }
                #[cfg(winapi = "syscall")]
                { |p, a| crate::Process::memory_information_syscall(p, a).map_err(|e| e.into()) }
            },
            is_done: false
        }
    }

    /// Official documentation: [kernel32.VirtualQueryEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex).
    ///
    /// Official documentation: [ntdll.NtQueryVirtualMemory](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvirtualmemory).
    ///
    /// Returns an iterator over basic information about the process memory.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn iter_memory_information_kernel32(&self, start_address: usize)
        -> BasicIterator<crate::error::Status>
    {
        BasicIterator {
            process: self,
            address: start_address,
            func: crate::Process::memory_information_kernel32,
            is_done: false
        }
    }

    /// Official documentation: [kernel32.VirtualQueryEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex).
    ///
    /// Official documentation: [ntdll.NtQueryVirtualMemory](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvirtualmemory).
    ///
    /// Returns an iterator over basic information about the process memory.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn iter_memory_information_ntdll(&self, start_address: usize)
        -> BasicIterator<crate::error::NtStatus>
    {
        BasicIterator {
            process: self,
            address: start_address,
            func: crate::Process::memory_information_ntdll,
            is_done: false
        }
    }

    /// Official documentation: [kernel32.VirtualQueryEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex).
    ///
    /// Official documentation: [ntdll.NtQueryVirtualMemory](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvirtualmemory).
    ///
    /// Returns an iterator over basic information about the process memory.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn iter_memory_information_syscall(&self, start_address: usize)
        -> BasicIterator<crate::error::NtStatus>
    {
        BasicIterator {
            process: self,
            address: start_address,
            func: crate::Process::memory_information_syscall,
            is_done: false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::memory::*;

    #[test]
    fn iter_memory_information() {
        crate::init_syscall_ids();

        let process = crate::Process::current();
        let address = crate::system::SharedData::get_user_mode() as *const _ as usize;
        let block = shared_data_block(address);

        let block_collections: [alloc::vec::Vec<_>; 4] = [
            crate::Process::iter_memory_information_kernel32(&process, address).collect(),
            crate::Process::iter_memory_information_ntdll(&process, address).collect(),
            crate::Process::iter_memory_information_syscall(&process, address).collect(),
            crate::Process::iter_memory_information(&process, address).collect()
        ];

        for blocks in block_collections {
            assert_eq!(blocks.iter().filter(|b| b == &&block).count(), 1);
        }
    }

    #[test]
    fn memory_information() {
        crate::init_syscall_ids();

        const FUNCTIONS: &[fn(&crate::Process, usize) -> Result<Basic, crate::error::Error>] = &[
            |p, a| crate::Process::memory_information_kernel32(p, a).map_err(|e| e.into()),
            |p, a| crate::Process::memory_information_ntdll(p, a).map_err(|e| e.into()),
            |p, a| crate::Process::memory_information_syscall(p, a).map_err(|e| e.into()),
            crate::Process::memory_information
        ];

        let process = crate::Process::current();
        let address = crate::system::SharedData::get_user_mode() as *const _ as usize;
        let block = shared_data_block(address);

        for f in FUNCTIONS {
            assert_eq!((*f)(&process, address).unwrap(), block);
        }
    }

    /// Creates a block which is based on the `struct KUSER_SHARED_DATA` memory page.
    fn shared_data_block(address: usize) -> Basic {
        Basic {
            base_address: address,
            allocation_base: address,
            allocation_protection: Protection::new().set_access(ProtectionAccess::Read),
            region_size: 0x1000,
            states: States::new().set(State::Commit, true),
            protection: Protection::new().set_access(ProtectionAccess::Read),
            kinds: Kinds::new().set(Kind::Private, true)
        }
    }
}