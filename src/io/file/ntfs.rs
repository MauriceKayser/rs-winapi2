//! All New Technology File System related Windows types.

/// Official documentation: [FILE_* enum](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_full_ea_information).
///
/// Unofficial documentation: [FILE_* enum](https://github.com/processhacker/phnt/blob/master/ntioapi.h).
#[bitfield::bitfield(8)]
#[derive(Copy, Clone, Debug, Display, Eq, PartialEq)]
pub struct ExtendedAttributeFlags(pub ExtendedAttributeFlag);

/// Official documentation: [FILE_* enum](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_full_ea_information).
///
/// Unofficial documentation: [FILE_* enum](https://github.com/processhacker/phnt/blob/master/ntioapi.h).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, bitfield::Flags)]
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