//! All New Technology File System related Windows types.

use enum_extensions::Iterator;

/// Official documentation: [FILE_* enum](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_full_ea_information).
///
/// Unofficial documentation: [FILE_* enum](https://github.com/processhacker/phnt/blob/master/ntioapi.h).
#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(C)]
pub struct ExtendedAttributeFlags(bitfield::BitField8);

/// Official documentation: [FILE_* enum](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_full_ea_information).
///
/// Unofficial documentation: [FILE_* enum](https://github.com/processhacker/phnt/blob/master/ntioapi.h).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, Iterator)]
#[repr(u8)]
pub enum ExtendedAttributeFlag {
    NeedKnowledge = 7
}

impl ExtendedAttributeFlags {
    /// Creates a new instance.
    #[inline(always)]
    pub const fn new() -> Self {
        Self(bitfield::BitField8::new())
    }

    /// Returns a modified variant with the flag set to the specified value.
    #[inline(always)]
    pub const fn set(&self, flag: ExtendedAttributeFlag, value: bool) -> Self {
        Self(self.0.set_bit(flag as u8, value))
    }
}

bitfield::impl_debug!(ExtendedAttributeFlags, ExtendedAttributeFlag::iter());

// TODO: Implement creation.
/// Official documentation: [FILE_FULL_EA_INFORMATION struct](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_full_ea_information).
#[allow(unused)]
#[repr(C)]
pub struct ExtendedAttributesInformation {
    next_entry_offset: u32,
    flags: ExtendedAttributeFlags,
    name_size: u8,
    value_size: u16
}