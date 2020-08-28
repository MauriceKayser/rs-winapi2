//! All New Technology File System related Windows types.

use enum_extensions::Iterator;

bitfield::bit_field!(
    /// Official documentation: [FILE_* enum](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_full_ea_information).
    ///
    /// Unofficial documentation: [FILE_* enum](https://github.com/processhacker/phnt/blob/master/ntioapi.h).
    #[derive(Copy, Clone, Eq, PartialEq)]
    pub ExtendedAttributeFlags: u8;
    flags:
        pub has + pub set: ExtendedAttributeFlag
);

/// Official documentation: [FILE_* enum](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_full_ea_information).
///
/// Unofficial documentation: [FILE_* enum](https://github.com/processhacker/phnt/blob/master/ntioapi.h).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, Iterator)]
#[repr(u8)]
pub enum ExtendedAttributeFlag {
    NeedKnowledge = 7
}

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