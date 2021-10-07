//! All types for parsing PE file exports.

/// An iterator over the exported functions and data.
pub struct Iterator<'a, 'b> {
    image: &'b mut super::PeFile<'a>,
    exclude_zero_terminator: bool,
    directory: &'a Directory,
    directory_size: u32,

    address_rvas: &'a [u32],
    name_rvas: &'a [u32],
    ordinals: &'a [u16],
    ordinal_base: u32,

    index: usize
}

impl<'a, 'b> Iterator<'a, 'b> {
    /// Creates an iterator over the exported functions and data.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn new(pe: &'b mut super::PeFile<'a>, exclude_zero_terminator: bool) -> Option<Self> {
        let (directory, directory_size) = pe.directory_export()?;

        let addresses_offset = pe.rva_to_offset(directory.addresses_rva);
        let names_offset = pe.rva_to_offset(directory.names_rva);
        let ordinals_offset = pe.rva_to_offset(directory.ordinals_rva);

        let addresses_max = pe.maximum_rest_of::<u32>(addresses_offset)?;
        let names_max = pe.maximum_rest_of::<u32>(names_offset)?;
        let ordinals_max = pe.maximum_rest_of::<u16>(ordinals_offset)?;

        unsafe {
            Some(Self {
                directory,
                directory_size,
                address_rvas: pe.slice_unchecked(
                    addresses_offset,
                    core::cmp::min(directory.addresses_count as usize, addresses_max)
                ),
                name_rvas: pe.slice_unchecked(
                    names_offset,
                    core::cmp::min(directory.names_count as usize, names_max)
                ),
                ordinals: pe.slice_unchecked(
                    ordinals_offset,
                    core::cmp::min(directory.names_count as usize, ordinals_max)
                ),
                ordinal_base: directory.ordinal_base,
                index: 0,
                image: pe,
                exclude_zero_terminator
            })
        }
    }
}

impl<'a, 'b> core::iter::Iterator for Iterator<'a, 'b> {
    type Item = Named<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let dir_offset = self.image.offset_of(self.directory);

        loop { unsafe {
            // Terminate the iterator, if the ordinal- or name index is out of bounds.
            let ordinal = self.ordinals.get(self.index)?;
            let name_offset = self.image.rva_to_offset(*self.name_rvas.get_unchecked(self.index));

            self.index += 1;

            // Skip this export, if the possible name length is <= 0.
            let max_name_len = match (self.image.image_base.len() as u32).checked_sub(name_offset) {
                Some(len) if len > 0 => core::num::NonZeroUsize::new_unchecked(len as usize),
                _ => continue
            };

            // Skip this export, if the ordinal overflows.
            let biased_ordinal = match self.ordinal_base.checked_add(*ordinal as u32) {
                Some(ord) => ord,
                _ => continue
            };

            // Skip this export, if the ordinal is out of bounds.
            let (address_rva, address_offset) = match self.address_rvas.get(*ordinal as usize) {
                Some(rva) => (rva, self.image.rva_to_offset(*rva)),
                None => continue
            };

            // Construct the export name.
            let name = crate::string::AnsiStr::from_terminated_with_offset(
                self.image.image_base.as_ptr(),
                name_offset as usize,
                Some(max_name_len),
                self.exclude_zero_terminator
            );

            // Is the offset not in bounds of the export directory?
            if !(dir_offset..dir_offset.unchecked_add(self.directory_size)).contains(&address_offset) {
                // Then it is a real export.

                // Check if the offset is inside the PE file.
                if (address_offset as usize) < self.image.image_base.len() {
                    let buffer = self.image.slice_unchecked(
                        address_offset,
                        self.image.image_base.len() - address_offset as usize
                    );

                    return Some(Named {
                        data: Data::InModule(buffer), name, address_rva, ordinal: biased_ordinal
                    });
                } else {
                    let address = self.image.offset_to_ptr(address_offset);

                    return Some(Named {
                        data: Data::OutOfModule(address), name, address_rva, ordinal: biased_ordinal
                    });
                }
            } else {
                // Otherwise it is a forwarded export.

                // Skip this export, if the possible forwarded name length is <= 0.
                let fwd_name_len = match self.image.image_base.len().checked_sub(address_offset as usize) {
                    Some(len) if len > 0 => core::num::NonZeroUsize::new_unchecked(len),
                    _ => continue
                };

                // Construct the forwarded name.
                let fwd_name = crate::string::AnsiStr::from_terminated_with_offset(
                    self.image.image_base.as_ptr(),
                    address_offset as usize,
                    Some(fwd_name_len),
                    self.exclude_zero_terminator
                );

                return Some(Named {
                    data: Data::Forwarded(fwd_name), name, address_rva, ordinal: biased_ordinal
                });
            }
        } }
    }
}

/// Stores the data which an export points at.
#[derive(Debug, Eq, PartialEq)]
pub enum Data<'a> {
    /// Data or a function in the PE file buffer.
    InModule(&'a [u8]),

    /// Data or a function outside of the PE file buffer.
    OutOfModule(*const u8),

    /// The name of the forwarded symbol.
    Forwarded(&'a crate::string::AnsiStr)
}

/// Stores details about an export by a PE file.
#[derive(Debug, Eq, PartialEq)]
pub struct Named<'a> {
    /// The data which the export points at.
    pub data: Data<'a>,

    /// The ASCII encoded, zero-terminated export name.
    pub name: &'a crate::string::AnsiStr,

    /// The reference to the address RVA.
    pub address_rva: &'a u32,

    /// The ordinal number of the export.
    pub ordinal: u32
}

#[repr(C)]
pub(super) struct Directory {
    _1: [u8; 16],
    ordinal_base: u32,
    addresses_count: u32,
    names_count: u32,
    addresses_rva: u32,
    names_rva: u32,
    ordinals_rva: u32
}

#[cfg(test)]
mod tests {
    use super::*;

    // Macros.

    macro_rules! parse {
        ( $( ($name:expr, $mode:ident, $result:expr, $buffer:expr) ),+ ) => {
            $(
                parse!($name, $mode, $result, $buffer);
            )+
        };
        ($name:expr, $mode:ident, $result:expr, $buffer:expr) => {{
            assert_eq!(
                super::super::PeFile::new($buffer, super::super::ParsingMode::$mode).exports(true).unwrap().collect::<alloc::vec::Vec<Named>>(),
                $result,
                "unexpected parsing result for {:?}", $name
            );
        }};
    }

    // Test macros.

    #[test]
    #[should_panic(expected = "unexpected parsing result for \"No exports\"")]
    fn validate_parse() {
        const BUFFER: &[u8] = &[
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
        ];

        parse!("No exports", Virtual, &[
            Named {
                data: Data::Forwarded(From::from("A".as_bytes())),
                name: From::from("B".as_bytes()),
                address_rva: unsafe { &*(BUFFER.as_ptr() as *const u32) },
                ordinal: 0
            }
        ], BUFFER);
    }

    // Test code.

    #[test]
    fn exports() {
        const BUFFER: &[u8] = &[
            /*  00 */ 0x4D,0x5A,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, // DH.magic = 0x5A4D
            /*  10 */ 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
            /*  20 */ 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
            /*  30 */ 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x40,0x00,0x00,0x00, // DH.coff_fo = 0x40
            /*  40 */ 0x50,0x45,0x00,0x00, 0x64,0x86,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, // CH.magic = 0x4550, CH.machine = 0x8664
            /*  50 */ 0x00,0x00,0x00,0x00, 0x78,0x00,0x00,0x00, 0x0B,0x02,0x00,0x00, 0x00,0x00,0x00,0x00, // CH.optional_header_size = 0x78, OH64.magic = 0x020B
            /*  60 */ 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
            /*  70 */ 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
            /*  80 */ 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
            /*  90 */ 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
            /*  A0 */ 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
            /*  B0 */ 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
            /*  C0 */ 0x00,0x00,0x00,0x00, 0x01,0x00,0x00,0x00, 0xD0,0x00,0x00,0x00, 0x4F,0x00,0x00,0x00, // OH64.data_directory_count = 1, Dir(Export).rva = 0xD0, Dir(Export).size = 0x28 + 3*4 + 3*4 + 3*2 + len("A\0") + len("B\0") + len("C.D\0") + len("E\0") = 0x4F
            /*  D0 */ 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
            /*  E0 */ 0x00,0x00,0x00,0x00, 0x03,0x00,0x00,0x00, 0x03,0x00,0x00,0x00, 0xF8,0x00,0x00,0x00, // EDir.ordinal_base: 0, EDir.addrs: 3, EDir.names: 3, EDir.addr_rva: 0xF8
            /*  F0 */ 0x04,0x01,0x00,0x00, 0x10,0x01,0x00,0x00, 0x02,0x00,0x00,0x00, 0x1A,0x01,0x00,0x00, // EDir.names_rva: 0x104, EDir.ordinal_rva: 0x110, EAddress 1: 0x02 (in module), EAddress 2: 0x11A (fwd)
            /* 100 */ 0x00,0x10,0x00,0x00, 0x16,0x01,0x00,0x00, 0x18,0x01,0x00,0x00, 0x1E,0x01,0x00,0x00, // EAddress 3: 0x1000 (out of module), EName 1: 0x116, EName 2: 0x118, EName 3: 0x11E
            /* 110 */ 0x00,0x00,0x01,0x00, 0x02,0x00,0x41,0x00, 0x42,0x00,0x43,0x2E, 0x44,0x00,0x45,0x00, // EOrdinal 1: 0, EOrdinal 2: 1, EOrdinal 3: 2, Name 1: "A\0", Name 2: "B\0", FwdName: "C.D\0", Name 3: "E\0"
        ];

        parse!(
            ("3 valid exports", Virtual, &[
                Named {
                    data: Data::InModule(&BUFFER[2..]),
                    name: From::from("A".as_bytes()),
                    address_rva: unsafe { &*(BUFFER.as_ptr().add(0xF8) as *const u32) },
                    ordinal: 0
                },
                Named {
                    data: Data::Forwarded(From::from("C.D".as_bytes())),
                    name: From::from("B".as_bytes()),
                    address_rva: unsafe { &*(BUFFER.as_ptr().add(0xFC) as *const u32) },
                    ordinal: 1
                },
                Named {
                    data: Data::OutOfModule(unsafe { BUFFER.as_ptr().add(0x1000) }),
                    name: From::from("E".as_bytes()),
                    address_rva: unsafe { &*(BUFFER.as_ptr().add(0x100) as *const u32) },
                    ordinal: 2
                },
            ], BUFFER)

            // TODO: Add test buffers which test edge cases.
        );
    }

    #[test]
    fn kernel32_exports() {
        let ldr_entry =
            unsafe { crate::process::EnvironmentBlock::current_from_block_teb() }.unwrap()
                .loader_data.as_ref().unwrap()
                // Current process image
                .load_order_next.as_ref().unwrap()
                // ntdll.dll
                .load_order_next.as_ref().unwrap()
                // kernel32.dll
                .load_order_next.as_ref().unwrap();

        let mut parser = ldr_entry.image_base_address.unwrap().create_parser(
            ldr_entry.image_virtual_size, super::super::ParsingMode::Virtual
        ).unwrap();

        let mut contains_add_atom_w = false;
        let mut contains_acquire_srw_lock_exclusive = false;

        for export in parser.exports(true).unwrap() {
            match export.data {
                Data::InModule(_) => {
                    if export.name == "AddAtomW" {
                        contains_add_atom_w = true;
                    }
                }
                Data::OutOfModule(address) => {
                    panic!(
                        "{:?} is most likely hooked to 0x{:X}",
                        export.name.into_lossy(),
                        address as usize
                    );
                }
                Data::Forwarded(forwarder) => {
                    if  export.name == "AcquireSRWLockExclusive" &&
                        forwarder == "NTDLL.RtlAcquireSRWLockExclusive"
                    {
                        contains_acquire_srw_lock_exclusive = true;
                    }
                }
            }

            if contains_add_atom_w && contains_acquire_srw_lock_exclusive {
                break;
            }
        }

        assert!(contains_add_atom_w && contains_acquire_srw_lock_exclusive);
    }
}