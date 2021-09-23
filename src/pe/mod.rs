//! All types for parsing a PE file.
//!
//! Based on: <https://docs.microsoft.com/en-us/windows/win32/debug/pe-format>.
//!
//! Use the `PeFile` type to get information about a PE file.

use core::mem::size_of;

pub mod base_relocation;
pub mod export;

/// A parser for PE files.
pub struct PeFile<'a> {
    pub(crate) image_base: &'a [u8],
    mode: ParsingMode,
    image_machine_type: Option<CoffMachine>,
    size_after_optional_header: Option<u16>,
    directories: Option<&'a [DataDirectory]>
}

impl<'a> PeFile<'a> {
    /// Creates a new PE file parser.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn new(image_base: &'a [u8], mode: ParsingMode) -> Self {
        Self {
            image_base,
            mode,
            image_machine_type: None,
            size_after_optional_header: None,
            directories: None
        }
    }

    /// Creates an iterator over the base relocations.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn base_relocations(&mut self) -> Option<base_relocation::Iterator<'a>> {
        base_relocation::Iterator::new(self)
    }

    /// Creates an iterator over the exported functions and data.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn exports<'b>(&'b mut self, exclude_zero_terminator: bool) -> Option<export::Iterator<'a, 'b>> {
        export::Iterator::new(self, exclude_zero_terminator)
    }

    /// Returns and caches the machine type of the PE file.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn machine_type(&mut self) -> Option<CoffMachine> {
        self.image_machine_type.or_else(|| self.coff_header().and_then(|header| {
            // Cache the machine type.
            let machine = CoffMachine::try_from(header.machine).ok();
            self.image_machine_type = machine;

            machine
        }))
    }

    // -- Private methods --

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn coff_header(&self) -> Option<&'a CoffHeader> {
        let header = unsafe { crate::conversion::cast::<CoffHeader>(
            self.image_base, self.dos_header()?.coff_fo as usize
        )? };

        if header.magic != CoffHeaderMagic::Coff as u32 {
            return None;
        }

        Some(header)
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn dos_header(&self) -> Option<&'a DosHeader> {
        let header = unsafe { crate::conversion::cast::<DosHeader>(
            self.image_base, 0
        )? };

        if header.magic != DosHeaderMagic::Dos as u16 {
            return None;
        }

        Some(header)
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn directory(&mut self, dir: DataDirectoryType) -> Option<&'a DataDirectory> {
        // Get result from cache.
        if let Some(directories) = self.directories {
            return directories.get(dir as usize);
        }

        // Cache the data directories.
        unsafe {
            // The data directories follow directly after the optional header.
            let (count, after_header_offset) = match self.optional_header()? {
                OptionalHeader::Pe64(header) => (
                    header.data_directory_count,
                    self.offset_after(header)
                ),

                OptionalHeader::Pe32(header) => (
                    header.data_directory_count,
                    self.offset_after(header)
                )
            };

            let directories_max = self.maximum_rest_of::<DataDirectory>(after_header_offset)?;

            self.directories = Some(self.slice_unchecked(
                after_header_offset, core::cmp::min(count as usize, directories_max)
            ));

            self.directories.unwrap_unchecked().get(dir as usize)
        }
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn directory_export(&mut self) -> Option<(&'a export::Directory, u32)> {
        let dir = self.directory(DataDirectoryType::Export)?;

        if size_of::<export::Directory>() > dir.size as usize {
            return None;
        }

        let export = unsafe { crate::conversion::cast::<export::Directory>(
            self.image_base, self.rva_to_offset(dir.rva) as usize
        )? };

        // Optionally shrink `dir.size` to the end of the buffer.
        let dir_offset = self.offset_of(export);
        let directory_to_buffer_end_length = unsafe {
            (self.image_base.len() as u32).unchecked_sub(dir_offset)
        };

        Some((export, core::cmp::min(dir.size, directory_to_buffer_end_length)))
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn optional_header(&mut self) -> Option<OptionalHeader<'a>> {
        let coff_header = self.coff_header()?;

        // Validate and cache the image machine type.
        if self.image_machine_type.is_none() {
            self.image_machine_type = Some(CoffMachine::try_from(coff_header.machine).ok()?);
        }

        // The optional header follows directly after the COFF header.
        let header_offset = unsafe { self.offset_after(coff_header) };

        let (optional_header, optional_header_size) =
            match unsafe { self.image_machine_type.unwrap_unchecked() }
        {
            CoffMachine::Amd64 => {
                let header = unsafe { crate::conversion::cast::<OptionalHeader64>(
                    self.image_base, header_offset as usize
                )? };

                if header.magic != OptionalHeaderMagic::Pe64 as u16 {
                    return None;
                }

                (OptionalHeader::Pe64(header), size_of::<OptionalHeader64>())
            },

            CoffMachine::I386 => {
                let header = unsafe { crate::conversion::cast::<OptionalHeader32>(
                    self.image_base, header_offset as usize
                )? };

                if header.magic != OptionalHeaderMagic::Pe32 as u16 {
                    return None;
                }

                (OptionalHeader::Pe32(header), size_of::<OptionalHeader32>())
            }
        };

        // Validate and cache the optional header size.
        if self.size_after_optional_header.is_none() {
            self.size_after_optional_header = Some(core::cmp::min(
                coff_header.optional_header_size as usize,
                unsafe { self.image_base.len().unchecked_sub(header_offset as usize) }
            ).checked_sub(optional_header_size)? as u16);
        }



        Some(optional_header)
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn rva_to_offset(&self, rva: u32) -> u32 {
        match self.mode {
            ParsingMode::Virtual => rva
        }
    }

    // -- Helper methods --

    /// Calculates the amount of `T` that fit into the buffer after the specified offset.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn maximum_rest_of<T>(&self, offset: u32) -> Option<usize> {
        use core::ops::Div;

        Some(
            self.image_base.len()
                .checked_sub(offset as usize)? // Rest of the buffer.
                .div(size_of::<T>()) // Convert buffer length to T count.
        )
    }

    /// Returns the offset after the type `T` which is part of the image buffer.
    #[cfg_attr(not(debug_assertions), inline(always))]
    unsafe fn offset_after<T>(&self, data: &'a T) -> u32 {
        (data as *const _ as usize)
            .unchecked_sub(self.image_base.as_ptr() as usize) // Offset of `data`.
            .unchecked_add(size_of::<T>()) as u32 // Offset after `data`.
    }

    /// Returns the offset of the type `T` which is part of the image buffer.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn offset_of<T>(&self, data: &'a T) -> u32 {
        unsafe {
            (data as *const _ as usize)
                .unchecked_sub(self.image_base.as_ptr() as usize) as u32 // Offset of `data`.
        }
    }

    /// Converts an offset into a pointer of `T` in the buffer.
    #[cfg_attr(not(debug_assertions), inline(always))]
    unsafe fn offset_to_ptr<T>(&self, offset: u32) -> *const T {
        (self.image_base.as_ptr() as usize).unchecked_add(offset as usize) as _
    }

    /// Forms a slice of `T` from an offset and a length.
    #[cfg_attr(not(debug_assertions), inline(always))]
    unsafe fn slice_unchecked<T>(&self, offset: u32, len: usize) -> &'a [T] {
        core::slice::from_raw_parts(
            (self.image_base.as_ptr() as usize).unchecked_add(offset as usize) as *const _,
            len
        )
    }
}

/// The way the PE file is laid out in memory.
#[derive(Eq, PartialEq)]
pub enum ParsingMode {
    // TODO: Implement `ParsingMode::File`.
    // /// Read from the raw file on disk.
    // File,

    /// The sections are mapped at their virtual offsets instead of their file offsets.
    Virtual
}

// -- PE file format data types below --

#[allow(missing_docs)]
#[repr(C)]
struct CoffHeader {
    magic: u32,
    machine: u16,
    _1: [u8; 14],
    optional_header_size: u16,
    _2: [u8; 2]
}

#[repr(u32)]
enum CoffHeaderMagic {
    Coff = 0x00004550
}

/// The CPU type which the PE file was compiled for.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, bitfield::FromPrimitive)]
#[repr(u16)]
pub enum CoffMachine {
    Amd64 = 0x8664,
    I386 = 0x014C
}

#[repr(C)]
struct DataDirectory {
    rva: u32,
    size: u32
}

#[allow(unused)]
#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone, Copy)]
#[repr(C)]
enum DataDirectoryType {
    Export,
    Import,
    Resource,
    Exception,
    Certificate,
    BaseRelocation,
    Debug,
    Architecture,
    GlobalPointer,
    ThreadLocalStorage,
    LoadConfig,
    BoundImport,
    ImportAddress,
    DelayImport,
    CommonLanguageRuntime,
    Reserved
}

#[allow(missing_docs)]
#[repr(C)]
pub struct DosHeader {
    magic: u16,
    _1: [u8; 0x3A],
    coff_fo: u32
}

impl DosHeader {
    /// Creates a new PE file parser.
    ///
    /// `image_size` refers to the size of the memory buffer, which is the raw file size in the
    /// `mode` `File` and the virtual size in the mode `Virtual`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn create_parser(&self, image_size: u32, mode: ParsingMode) -> Option<PeFile> {
        (size_of::<Self>() <= image_size as usize).then(
            || PeFile::new(unsafe { core::slice::from_raw_parts(
                self as *const DosHeader as *const _, image_size as usize
            ) }, mode)
        )
    }
}

impl core::fmt::Debug for DosHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct(stringify!(DosHeader))
            .field(stringify!(magic), &self.magic)
            .field(stringify!(coff_fo), &self.coff_fo)
            .finish()
    }
}

#[repr(u16)]
enum DosHeaderMagic {
    Dos = 0x5A4D
}

enum OptionalHeader<'a> {
    Pe32(&'a OptionalHeader32),
    Pe64(&'a OptionalHeader64)
}

#[repr(C)]
struct OptionalHeader32 {
    magic: u16,
    _1: [u8; 0x5A],
    data_directory_count: u32
}

#[repr(C)]
struct OptionalHeader64 {
    magic: u16,
    _1: [u8; 0x6A],
    data_directory_count: u32
}

#[repr(u16)]
enum OptionalHeaderMagic {
    Pe32 = 0x010B,
    Pe64 = 0x020B
}

#[cfg(test)]
mod tests {
    use super::*;

    // Macros.

    macro_rules! parse {
        ( $( ($name:expr, $mode:ident, $parser:ident, $valid:expr, $buffer:expr) ),+ ) => {
            $(
                parse!($name, $mode, $parser, $valid, $buffer);
            )+
        };
        ($name:expr, $mode:ident, $parser:ident, $valid:expr, $buffer:expr) => {{
            assert_eq!(
                PeFile::new($buffer, ParsingMode::$mode).$parser().is_some(),
                $valid,
                "unexpected parsing result for {:?}", $name
            );
        }};
    }

    // Test macros.

    #[test]
    #[should_panic(expected = "unexpected parsing result for \"Empty file\"")]
    fn validate_parse() {
        parse!("Empty file", Virtual, dos_header, true, &[]);
    }

    // Test code.

    #[test]
    fn parse_virtual() {
        parse![
            ("Invalid DOS size, empty", Virtual, dos_header, false, &[]),
            ("Invalid DOS size, one off", Virtual, dos_header, false, &[
                0x4D,0x5A,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
            ]),
            ("Invalid DOS magic", Virtual, dos_header, false, &[
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
            ]),
            ("Correct DOS header", Virtual, dos_header, true, &[
                0x4D,0x5A,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
            ]),

            (r"Invalid COFF magic, MZ\0\0", Virtual, coff_header, false, &[
                0x4D,0x5A,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
            ]),
            (r"Invalid COFF magic \0\0\0\0", Virtual, coff_header, false, &[
                0x4D,0x5A,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00
            ]),
            ("Invalid COFF size, one off", Virtual, coff_header, false, &[
                0x4D,0x5A,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x50,0x45,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x29,0x00,0x00,0x00
            ]),
            ("Valid COFF header", Virtual, coff_header, true, &[
                0x4D,0x5A,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x50,0x45,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x28,0x00,0x00,0x00
            ]),

            ("Invalid COFF machine", Virtual, optional_header, false, &[
                0x4D,0x5A,0x50,0x45,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x60,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
            ]),
            ("Valid x64 optional header", Virtual, optional_header, true, &[
                0x4D,0x5A,0x50,0x45,0x00,0x00,0x64,0x86,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x00,0x00,0x0B,0x02,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
            ]),
            ("Invalid x64 optional header size, field data", Virtual, optional_header, false, &[
                0x4D,0x5A,0x50,0x45,0x00,0x00,0x64,0x86,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x6F,0x00,0x00,0x00,0x0B,0x02,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
            ]),
            ("Invalid x64 optional header size, one off", Virtual, optional_header, false, &[
                0x4D,0x5A,0x50,0x45,0x00,0x00,0x64,0x86,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x00,0x00,0x0B,0x02,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
            ]),
            ("Valid x86 optional header", Virtual, optional_header, true, &[
                0x4D,0x5A,0x50,0x45,0x00,0x00,0x4C,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x60,0x00,0x00,0x00,0x0B,0x01,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
            ]),
            ("Invalid x86 optional header size, field data", Virtual, optional_header, false, &[
                0x4D,0x5A,0x50,0x45,0x00,0x00,0x4C,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x5F,0x00,0x00,0x00,0x0B,0x01,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
            ]),
            ("Invalid x86 optional header size, one off", Virtual, optional_header, false, &[
                0x4D,0x5A,0x50,0x45,0x00,0x00,0x4C,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x60,0x00,0x00,0x00,0x0B,0x01,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
            ]),
            ("Invalid COFF x86 machine + x64 optional header combo", Virtual, optional_header, false, &[
                0x4D,0x5A,0x50,0x45,0x00,0x00,0x4C,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x00,0x00,0x0B,0x02,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
            ]),
            ("Invalid COFF x64 machine + x86 optional header combo", Virtual, optional_header, false, &[
                0x4D,0x5A,0x50,0x45,0x00,0x00,0x64,0x86,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x00,0x00,0x0B,0x01,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
            ]),

            ("Invalid number of directories", Virtual, directory_export, false, &[
                0x4D,0x5A,0x50,0x45,0x00,0x00,0x64,0x86,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x00,0x00,0x0B,0x02,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00
            ]),
            ("Invalid directory, out of optional header size", Virtual, directory_export, false, &[
                0x4D,0x5A,0x50,0x45,0x00,0x00,0x64,0x86,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x77,0x00,0x00,0x00,0x0B,0x02,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00
            ]),
            ("Invalid ExportDirectory size, one off", Virtual, directory_export, false, &[
                0x4D,0x5A,0x50,0x45,0x00,0x00,0x64,0x86,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x78,0x00,0x00,0x00,0x0B,0x02,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x6B,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00
            ]),
            ("Invalid ExportDirectory size, field data", Virtual, directory_export, false, &[
                0x4D,0x5A,0x50,0x45,0x00,0x00,0x64,0x86,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x78,0x00,0x00,0x00,0x0B,0x02,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x30,0x00,0x00,0x00,0x27,0x00,
                0x00,0x00
            ]),
            ("Valid ExportDirectory", Virtual, directory_export, true, &[
                0x4D,0x5A,0x50,0x45,0x00,0x00,0x64,0x86,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x78,0x00,0x00,0x00,0x0B,0x02,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x30,0x00,0x00,0x00,0x28,0x00,
                0x00,0x00
            ])
            /*
                0x4D,0x5A,0x50,0x45,0x00,0x00, Machine ,NrOfSects,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,SizOptHdr,Chrctrscs, OHMagic ,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,
	             ExportOrdinalBase , ExportAddressCount,  ExportNamesCount ,ExportAddressTblRVA,
	            ExportNamesTableRVA,ExportOrdinalTblRVA,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	            0x00,0x00,0x00,0x00,0x00,0x00,NumberOfDirectories,ExportRelativeVAddr,ExportDire
	            ctorySize
            ])
            */
        ];
    }
}