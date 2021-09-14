//! All types for parsing PE file base relocations.

/// An iterator over the base relocations.
pub struct Iterator<'a> {
    buffer: &'a [u8]
}

impl<'a> Iterator<'a> {
    /// Creates an iterator over the base relocations.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn new(pe: &mut super::PeFile<'a>) -> Option<Self> {
        let directory = pe.directory(super::DataDirectoryType::BaseRelocation)?;

        let directory_offset = pe.rva_to_offset(directory.rva);
        let buffer_max = pe.maximum_rest_of::<u8>(directory_offset)?;

        unsafe {
            Some(Self {
                buffer: pe.slice_unchecked(
                    directory_offset,
                    core::cmp::min(directory.size as usize, buffer_max)
                )
            })
        }
    }
}

impl<'a> core::iter::Iterator for Iterator<'a> {
    type Item = Block<'a>;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn next(&mut self) -> Option<Self::Item> {
        let block = unsafe { crate::conversion::cast::<RelocationBlock>(self.buffer, 0)? };

        let min_length = core::cmp::min(self.buffer.len(), block.size as usize);

        let entry_data = &self.buffer[
            core::cmp::min(core::mem::size_of::<RelocationBlock>(), min_length)
            ..
            min_length
        ];

        // Advance the buffer position and safeguard against infinite loops.
        self.buffer = &self.buffer[if min_length > 0 { min_length } else { self.buffer.len() }..];

        Some(Block { page_rva: block.page_rva, buffer: entry_data })
    }
}

/// Stores details about a base relocation block.
#[derive(Debug, Eq, PartialEq)]
pub struct Block<'a> {
    /// The base relocation table is divided into blocks. Each block represents the base relocations
    /// for a 4K page. Each block must start on a 32-bit boundary.
    pub page_rva: u32,
    buffer: &'a [u8]
}

impl<'a> Block<'a> {
    /// Returns an iterator over the entries in this base relocation block.
    pub fn entries(&self) -> EntryIterator<'a> {
        EntryIterator { buffer: self.buffer }
    }
}

/// Stores details about an entry in a `Block`.
#[allow(missing_docs)]
#[derive(Debug, Eq, PartialEq)]
pub enum Entry {
    Standard { offset: u16, kind: Result<Kind, u8> },
    /// The base relocation adds the high 16 bits of the difference to the 16-bit field at offset.
    /// The 16-bit field represents the high value of a 32-bit word. The low 16 bits of the 32-bit
    /// value are stored in the 16-bit word that follows this base relocation.
    Adjusted { offset: u16, adjustment: u16 }
}

/// An iterator over the entries in a base relocation block.
pub struct EntryIterator<'a> {
    buffer: &'a [u8]
}

impl<'a> core::iter::Iterator for EntryIterator<'a> {
    type Item = Entry;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn next(&mut self) -> Option<Self::Item> {
        let entry = unsafe { crate::conversion::cast::<RelocationEntry>(self.buffer, 0)? };

        Some(match entry.kind() {
            Ok(RelocationKind::WordHighAdjust) => {
                // In case of `IMAGE_REL_BASED_HIGHADJ`, a `u16` follows in the buffer.
                let adjustment = unsafe { *crate::conversion::cast::<u16>(
                    self.buffer, core::mem::size_of::<RelocationEntry>()
                )? };

                // Advance the buffer position.
                self.buffer = &self.buffer[core::mem::size_of::<RelocationEntry>() + core::mem::size_of::<u16>()..];

                Entry::Adjusted { offset: entry.offset(), adjustment }
            },

            _ => {
                // Advance the buffer position.
                self.buffer = &self.buffer[core::mem::size_of::<RelocationEntry>()..];

                let kind = entry.kind().map(|kind| unsafe { core::mem::transmute(kind) });

                Entry::Standard { offset: entry.offset(), kind }
            }
        })
    }
}

// TODO: Keep in sync with `RelocationKind`.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Kind {
    Padding,
    WordHigh,
    WordLow,
    DWord,
    // Variants 4 - 8 are reserved.
    /// `IMAGE_REL_BASED_IA64_IMM64`, not officially documented.
    IA64Instruction = 9,
    QWord
    // Variants 11 - 15 are reserved.
}

#[repr(C)]
struct RelocationBlock {
    page_rva: u32,
    size: u32
}

#[bitfield::bitfield(16)]
struct RelocationEntry {
    #[field(size = 12)] offset: u16,
    #[field(size = 4)] kind: RelocationKind
}

// TODO: Keep in sync with `Kind`.
#[derive(Clone, Copy, bitfield::Field)]
#[repr(u8)]
enum RelocationKind {
    Padding,
    WordHigh,
    WordLow,
    DWord,
    WordHighAdjust,
    // Variants 5 - 8 are reserved.
    IA64Instruction = 9,
    QWord
    // Variants 11 - 15 are reserved.
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    // TODO: Test and replicate how the Windows loader reacts to:
    //  - block.size is not padded (one or both of the last 2 bits is set)
    //  - WordHighAdjust needs 2 * u16, but block/directory size only provides 1 * u16
    //  - block/directory size is between 0 and 9
    //  - block.size > directory.size

    #[test]
    fn all_kinds() {
        const DATA: &[(&[u8], &[(u32, &[Entry])])] = &[
            // Empty
            (&[], &[]),

            // The buffer is too small
            (
                &[
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00
                ], &[]
            ),

            // Block.size = 0
            (
                &[
                    0x01, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00
                ],
                &[(1, &[])]
            ),

            // Block.size = 9
            (
                &[
                    0x02, 0x00, 0x00, 0x00,
                    0x09, 0x00, 0x00, 0x00
                ],
                &[(2, &[])]
            ),

            // Block.size = 10, but the buffer is too short
            (
                &[
                    0x03, 0x00, 0x00, 0x00,
                    0x0A, 0x00, 0x00, 0x00,

                    0b0000_0000
                ],
                &[(3, &[])]
            ),

            // Kind: Padding
            (
                &[
                    0x04, 0x00, 0x00, 0x00,
                    0x0A, 0x00, 0x00, 0x00,

                    0b0000_0001, 0b0000_0000
                ],
                &[
                    (4, &[
                        Entry::Standard { offset: 1, kind: Ok(Kind::Padding) }
                    ])
                ]
            ),

            // Kind: Padding + max offset
            (
                &[
                    0x05, 0x00, 0x00, 0x00,
                    0x0A, 0x00, 0x00, 0x00,

                    0b1111_1111, 0b0000_1111
                ],
                &[
                    (5, &[
                        Entry::Standard { offset: (1 << 12) - 1, kind: Ok(Kind::Padding) }
                    ])
                ]
            ),

            // Kind: WordHigh
            (
                &[
                    0x06, 0x00, 0x00, 0x00,
                    0x0A, 0x00, 0x00, 0x00,

                    0b0000_0001, 0b0001_0000
                ],
                &[
                    (6, &[
                        Entry::Standard { offset: 1, kind: Ok(Kind::WordHigh) }
                    ])
                ]
            ),

            // Kind: WordHighAdjust, but the buffer is too small
            (
                &[
                    0x07, 0x00, 0x00, 0x00,
                    0x0C, 0x00, 0x00, 0x00,

                    0b0000_0001, 0b0100_0000,
                    0b0000_0000
                ],
                &[
                    (7, &[])
                ]
            ),

            // Kind: WordHighAdjust, but the block.size is too small
            (
                &[
                    0x08, 0x00, 0x00, 0x00,
                    0x0B, 0x00, 0x00, 0x00,

                    0b0000_0001, 0b0100_0000,
                    0b0000_0000, 0b0000_0000
                ],
                &[
                    (8, &[])
                ]
            ),

            // Kind: WordHighAdjust, block too small
            (
                &[
                    0x09, 0x00, 0x00, 0x00,
                    0x0C, 0x00, 0x00, 0x00,

                    0b0000_0001, 0b0100_0000,
                    0b0000_0010, 0b0000_0001
                ],
                &[
                    (9, &[
                        Entry::Adjusted { offset: 1, adjustment: (1 << 1 | 1 << 8) }
                    ])
                ]
            ),

            // Kind: Undefined
            (
                &[
                    0x0A, 0x00, 0x00, 0x00,
                    0x0A, 0x00, 0x00, 0x00,

                    0b0000_0001, 0b1111_0000
                ],
                &[
                    (10, &[
                        Entry::Standard { offset: 1, kind: Err(0b1111) }
                    ])
                ]
            ),

            // Kind: Padding + too small
            (
                &[
                    0x0B, 0x00, 0x00, 0x00,
                    0x0A, 0x00, 0x00, 0x00,

                    0b0000_0001, 0b0000_0000,

                    0x0C, 0x00, 0x00, 0x00,
                    0x0A, 0x00, 0x00
                ],
                &[
                    (11, &[
                        Entry::Standard { offset: 1, kind: Ok(Kind::Padding) }
                    ])
                ]
            ),

            // Kind: Padding + WordHigh
            (
                &[
                    0x0D, 0x00, 0x00, 0x00,
                    0x0A, 0x00, 0x00, 0x00,

                    0b0000_0001, 0b0000_0000,

                    0x0E, 0x00, 0x00, 0x00,
                    0x0A, 0x00, 0x00, 0x00,

                    0b0000_0010, 0b0001_0000
                ],
                &[
                    (13, &[
                        Entry::Standard { offset: 1, kind: Ok(Kind::Padding) }
                    ]),
                    (14, &[
                        Entry::Standard { offset: 2, kind: Ok(Kind::WordHigh) }
                    ])
                ]
            ),

            // Block.size = 4 + Padding
            (
                &[
                    0x0F, 0x00, 0x00, 0x00,
                    0x04, 0x00, 0x00, 0x00, // &block[0].size = 4, &block[1].page_rva = 4
                    0x0A, 0x00, 0x00, 0x00,

                    0b0000_0001, 0b0000_0000
                ],
                &[
                    (15, &[]),
                    (4, &[
                        Entry::Standard { offset: 1, kind: Ok(Kind::Padding) }
                    ])
                ]
            )
        ];

        for (buffer, results) in DATA {
            let actual = Iterator { buffer }.map(
                |block| (block.page_rva, block.entries().collect::<Vec<_>>())
            ).collect::<Vec<_>>();
            let actual = actual.iter().map(
                |(block, entries)| (*block, entries.as_slice())
            ).collect::<Vec<_>>();

            assert_eq!(*results, actual.as_slice());
        }
    }
}