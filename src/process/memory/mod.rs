//! All process memory related Windows types.

pub mod info;

#[repr(u32)]
pub(crate) enum Information {
    Basic
}

/// Official documentation: [MEMORY_BASIC_INFORMATION struct](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information).
///
/// Official documentation: [kernel32.VirtualAllocEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex).
///
/// Official documentation: [kernel32.MapViewOfFile3](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile3).
#[bitfield::bitfield(32, allow_overlaps)]
#[derive(Copy, Clone, Debug, Display, Eq, PartialEq)]
pub struct Kinds(pub Kind);

/// Official documentation: [MEMORY_BASIC_INFORMATION struct](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information).
///
/// Official documentation: [kernel32.VirtualAllocEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex).
///
/// Official documentation: [kernel32.MapViewOfFile3](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile3).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, bitfield::Flags)]
#[repr(u8)]
pub enum Kind {
    Private = 17,
    Mapped,
    Image = 24
}

/// Official documentation: [Memory Protection Constants](https://docs.microsoft.com/en-us/windows/desktop/Memory/memory-protection-constants).
///
/// Unofficial documentation: [ProcessHacker](https://github.com/processhacker/processhacker/blob/master/phnt/include/ntmmapi.h).
#[bitfield::bitfield(32, allow_overlaps)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Protection {
    #[field(size = 8)]
    pub access: ProtectionAccess,
    pub flag: ProtectionFlag,
    pub flag_alloc: ProtectionFlagAlloc,
    pub flag_enclave: ProtectionFlagEnclave,
    pub flag_protect: ProtectionFlagProtect,
    pub flag_unknown: ProtectionFlagUnknown
}

// Getters for specific access flags.
impl Protection {
    #[allow(missing_docs)]
    #[cfg(const_trait_impl)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub const fn copy_on_write(&self) -> bool {
        match self.access() {
            Ok(ProtectionAccess::ReadWriteCopy) |
            Ok(ProtectionAccess::ExecuteReadWriteCopy) => true,
            _ => false
        }
    }

    // TODO: Remove when https://github.com/rust-lang/rfcs/pull/2632 is merged.
    #[allow(missing_docs)]
    #[cfg(not(const_trait_impl))]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn copy_on_write(&self) -> bool {
        match self.access() {
            Ok(ProtectionAccess::ReadWriteCopy) |
            Ok(ProtectionAccess::ExecuteReadWriteCopy) => true,
            _ => false
        }
    }

    #[allow(missing_docs)]
    #[cfg(const_trait_impl)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub const fn execute(&self) -> bool {
        match self.access() {
            Ok(ProtectionAccess::Execute) |
            Ok(ProtectionAccess::ExecuteRead) |
            Ok(ProtectionAccess::ExecuteReadWrite) |
            Ok(ProtectionAccess::ExecuteReadWriteCopy) => true,
            _ => false
        }
    }

    // TODO: Remove when https://github.com/rust-lang/rfcs/pull/2632 is merged.
    #[allow(missing_docs)]
    #[cfg(not(const_trait_impl))]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn execute(&self) -> bool {
        match self.access() {
            Ok(ProtectionAccess::Execute) |
            Ok(ProtectionAccess::ExecuteRead) |
            Ok(ProtectionAccess::ExecuteReadWrite) |
            Ok(ProtectionAccess::ExecuteReadWriteCopy) => true,
            _ => false
        }
    }

    #[allow(missing_docs)]
    #[cfg(const_trait_impl)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub const fn read(&self) -> bool {
        match self.access() {
            Ok(ProtectionAccess::Read) |
            Ok(ProtectionAccess::ReadWrite) |
            Ok(ProtectionAccess::ReadWriteCopy) |
            Ok(ProtectionAccess::ExecuteRead) |
            Ok(ProtectionAccess::ExecuteReadWrite) |
            Ok(ProtectionAccess::ExecuteReadWriteCopy) => true,
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Ok(ProtectionAccess::Execute) => true,
            _ => false
        }
    }

    // TODO: Remove when https://github.com/rust-lang/rfcs/pull/2632 is merged.
    #[allow(missing_docs)]
    #[cfg(not(const_trait_impl))]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn read(&self) -> bool {
        match self.access() {
            Ok(ProtectionAccess::Read) |
            Ok(ProtectionAccess::ReadWrite) |
            Ok(ProtectionAccess::ReadWriteCopy) |
            Ok(ProtectionAccess::ExecuteRead) |
            Ok(ProtectionAccess::ExecuteReadWrite) |
            Ok(ProtectionAccess::ExecuteReadWriteCopy) => true,
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Ok(ProtectionAccess::Execute) => true,
            _ => false
        }
    }

    #[allow(missing_docs)]
    #[cfg(const_trait_impl)]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub const fn write(&self) -> bool {
        match self.access() {
            Ok(ProtectionAccess::ReadWrite) |
            Ok(ProtectionAccess::ReadWriteCopy) |
            Ok(ProtectionAccess::ExecuteReadWrite) |
            Ok(ProtectionAccess::ExecuteReadWriteCopy) => true,
            _ => false
        }
    }

    // TODO: Remove when https://github.com/rust-lang/rfcs/pull/2632 is merged.
    #[allow(missing_docs)]
    #[cfg(not(const_trait_impl))]
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn write(&self) -> bool {
        match self.access() {
            Ok(ProtectionAccess::ReadWrite) |
            Ok(ProtectionAccess::ReadWriteCopy) |
            Ok(ProtectionAccess::ExecuteReadWrite) |
            Ok(ProtectionAccess::ExecuteReadWriteCopy) => true,
            _ => false
        }
    }
}

/// Part of [Protection].
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, bitfield::Field)]
#[repr(u8)]
pub enum ProtectionAccess {
    // 0 is reserved.
    None = 1 << 0,
    Read = 1 << 1,
    ReadWrite = 1 << 2,
    ReadWriteCopy = 1 << 3,
    Execute = 1 << 4,
    ExecuteRead = 1 << 5,
    ExecuteReadWrite = 1 << 6,
    ExecuteReadWriteCopy = 1 << 7
}

/// Part of [Protection].
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, bitfield::Flags)]
#[repr(u8)]
pub enum ProtectionFlag {
    Guard = 9,
    NoCache,
    WriteCombine
    // Bits 11 - 28 are reserved.
}

/// Part of [Protection].
///
/// To be used by `VirtualAlloc`.
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, bitfield::Flags)]
#[repr(u8)]
pub enum ProtectionFlagAlloc {
    TargetsInvalid = 30
}

/// Part of [Protection].
///
/// To be used by `LoadEnclaveData`.
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, bitfield::Flags)]
#[repr(u8)]
pub enum ProtectionFlagEnclave {
    Unvalidated = 29,
    ThreadControl = 31
}

/// Part of [Protection].
///
/// To be used by `VirtualProtect`.
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, bitfield::Flags)]
#[repr(u8)]
pub enum ProtectionFlagProtect {
    TargetsNoUpdate = 30
}

/// Part of [Protection].
///
/// Usage unknown.
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, bitfield::Flags)]
#[repr(u8)]
pub enum ProtectionFlagUnknown {
    RevertToFileMap = 31
}

/// Official documentation: [MEMORY_BASIC_INFORMATION struct](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information).
///
/// Official documentation: [kernel32.VirtualAllocEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex).
///
/// Official documentation: [kernel32.MapViewOfFile3](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile3).
#[bitfield::bitfield(32, allow_overlaps)]
#[derive(Copy, Clone, Debug, Display, Eq, PartialEq)]
pub struct States(pub State);

/// Official documentation: [MEMORY_BASIC_INFORMATION struct](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information).
///
/// Official documentation: [kernel32.VirtualAllocEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex).
///
/// Official documentation: [kernel32.MapViewOfFile3](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile3).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, bitfield::Flags)]
#[repr(u8)]
pub enum State {
    Commit = 12,
    Reserve,
    ReplacePlaceholder,
    Free = 16,
    Reset = 19,
    TopDown,
    WriteWatch,
    Physical,
    ResetUndo = 24,
    LargePages = 29
}