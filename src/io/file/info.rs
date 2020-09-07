//! All file information related Windows types.

/// Official documentation: [WIN32_FILE_ATTRIBUTE_DATA struct](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-win32_file_attribute_data).
#[allow(missing_docs)]
#[repr(C)]
pub struct BasicKernel32 {
    pub attributes: crate::io::file::Attributes,
    pub creation_time: crate::io::file::Time,
    pub last_access_time: crate::io::file::Time,
    pub last_write_time: crate::io::file::Time,
    file_size_high: u32,
    file_size_low: u32
}

impl BasicKernel32 {
    /// Returns the amount of stored bytes on disk.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub const fn file_size(&self) -> u64 {
        self.file_size_low as u64 | ((self.file_size_high as u64) << 32)
    }
}

impl core::fmt::Debug for BasicKernel32 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct(stringify!(BasicKernel32))
            .field(stringify!(attributes), &self.attributes)
            .field(stringify!(creation_time), &self.creation_time)
            .field(stringify!(last_acces_time), &self.last_access_time)
            .field(stringify!(last_write_time), &self.last_write_time)
            .field(stringify!(file_size), &self.file_size())
            .finish()
    }
}

/// Official documentation: [FILE_NETWORK_OPEN_INFORMATION struct](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_network_open_information).
#[allow(missing_docs)]
#[derive(Debug, Eq, PartialEq)]
#[repr(C)]
pub struct BasicNtDll {
    pub creation_time: crate::io::file::Time,
    pub last_access_time: crate::io::file::Time,
    pub last_write_time: crate::io::file::Time,
    pub change_time: crate::io::file::Time,
    /// The reserved space on disk (>= `file_size`).
    pub allocation_size: u64,
    /// The amount of stored bytes on disk.
    pub file_size: u64,
    pub attributes: crate::io::file::Attributes
}

#[cfg(test)]
mod test {
    use crate::string::*;

    #[test]
    fn basic() {
        let kernel32_path = String::from("C:\\Windows\\notepad.exe\0");
        let kernel32 = crate::io::file::Object::information_kernel32(
            kernel32_path.as_ref()
        ).unwrap();

        let ntdll_path = String::from(r"\??\C:\Windows\notepad.exe");
        let ntdll_path = StringW::from(ntdll_path.as_ref());
        let object_attributes = crate::object::Attributes::from_name(&ntdll_path);
        let ntdll = crate::io::file::Object::information_ntdll(&object_attributes).unwrap();

        assert_eq!(ntdll.creation_time, kernel32.creation_time);
        assert_eq!(ntdll.last_access_time, kernel32.last_access_time);
        assert_eq!(ntdll.last_write_time, kernel32.last_write_time);
        assert_eq!(ntdll.file_size, kernel32.file_size());
        assert_eq!(ntdll.attributes, kernel32.attributes);
    }
}