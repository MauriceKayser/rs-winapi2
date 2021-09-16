//! Direct implementation for the exports by several Windows dynamically loaded libraries.

/// Table that stores all system call ids which might get used by the internal functions.
#[allow(missing_docs)]
pub struct Ids {
    pub close: u16,
    pub create_file: u16,
    pub open_process: u16,
    pub query_full_attributes_file: u16,
    pub query_information_file: u16,
    pub query_information_process: u16,
    pub query_system_information: u16,
    pub read_file: u16,
    pub terminate_process: u16,
    pub write_file: u16
}

/// Global instance of system call ids that is used by all internal functions.
pub static mut IDS: Option<Ids> = None;

// IDs from:
// - https://hfiref0x.github.io/syscalls.html
// - https://j00ru.vexillium.org/syscalls/nt/32/
// - https://j00ru.vexillium.org/syscalls/nt/64/
impl Ids {
    /// Initializes the system call id table. Supports `Windows 8` - `Windows 10 21H1`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn initialize_statically() -> bool {
        const WINDOWS_VERSION_MIN: crate::system::ReleaseVersion = crate::system::ReleaseVersion::Eight;
        const WINDOWS_VERSION_MAX: crate::system::ReleaseVersion = crate::system::ReleaseVersion::Ten21H1;
        const SYSCALL_APIS: usize = 10;
        const SYSCALL_VERSIONS: usize = WINDOWS_VERSION_MAX as usize - WINDOWS_VERSION_MIN as usize + 1;

        #[cfg(target_arch = "x86")]
        const SYSCALL_IDS: [[u16; SYSCALL_VERSIONS]; SYSCALL_APIS] = [
            // Windows Version                8       8       10      10      10      10      10      10      10      10      10      10      10      10
            //                                8.0     8.1     1507    1511    1607    1703    1709    1803    1809    1903    1909    2004    20H2    21H1
            /* NtClose */                   [ 0x0174, 0x0179, 0x0180, 0x0183, 0x0185, 0x018A, 0x018D, 0x018D, 0x018D, 0x018D, 0x018D, 0x018E, 0x018E, 0x018E ],
            /* NtCreateFile */              [ 0x0163, 0x0168, 0x016E, 0x0170, 0x0172, 0x0175, 0x0178, 0x0178, 0x0178, 0x0178, 0x0178, 0x0178, 0x0178, 0x0178 ],
            /* NtOpenProcess */             [ 0x00DD, 0x00E0, 0x00E3, 0x00E3, 0x00E5, 0x00E7, 0x00E9, 0x00E9, 0x00E9, 0x00E9, 0x00E9, 0x00E9, 0x00E9, 0x00E9 ],
            /* NtQueryFullAttributesFile */ [ 0x00B6, 0x00B9, 0x00BB, 0x00BB, 0x00BD, 0x00BF, 0x00C0, 0x00C0, 0x00C0, 0x00C0, 0x00C0, 0x00C0, 0x00C0, 0x00C0 ],
            /* NtQueryInformationFile */    [ 0x00B3, 0x00B6, 0x00B8, 0x00B8, 0x00BA, 0x00BB, 0x00BC, 0x00BC, 0x00BC, 0x00BC, 0x00BC, 0x00BC, 0x00BC, 0x00BC ],
            /* NtQueryInformationProcess */ [ 0x00B0, 0x00B3, 0x00B5, 0x00B5, 0x00B7, 0x00B8, 0x00B9, 0x00B9, 0x00B9, 0x00B9, 0x00B9, 0x00B9, 0x00B9, 0x00B9 ],
            /* NtQuerySystemInformation */  [ 0x0095, 0x0098, 0x009A, 0x009A, 0x009B, 0x009C, 0x009D, 0x009D, 0x009D, 0x009D, 0x009D, 0x009D, 0x009D, 0x009D ],
            /* NtReadFile */                [ 0x0087, 0x008A, 0x008C, 0x008C, 0x008D, 0x008D, 0x008E, 0x008E, 0x008E, 0x008E, 0x008E, 0x008E, 0x008E, 0x008E ],
            /* NtTerminateProcess */        [ 0x0023, 0x0023, 0x0024, 0x0024, 0x0024, 0x0024, 0x0024, 0x0024, 0x0024, 0x0024, 0x0024, 0x0024, 0x0024, 0x0024 ],
            /* NtWriteFile */               [ 0x0005, 0x0006, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007, 0x0007 ],
        ];
        #[cfg(target_arch = "x86_64")]
        const SYSCALL_IDS: [[u16; SYSCALL_VERSIONS]; SYSCALL_APIS] = [
            // Windows Version                8       8       10      10      10      10      10      10      10      10      10      10      10      10
            //                                8.0     8.1     1507    1511    1607    1703    1709    1803    1809    1903    1909    2004    20H2    21H1
            /* NtClose */                   [ 0x000D, 0x000E, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F, 0x000F ],
            /* NtCreateFile */              [ 0x0053, 0x0054, 0x0055, 0x0055, 0x0055, 0x0055, 0x0055, 0x0055, 0x0055, 0x0055, 0x0055, 0x0055, 0x0055, 0x0055 ],
            /* NtOpenProcess */             [ 0x0024, 0x0025, 0x0026, 0x0026, 0x0026, 0x0026, 0x0026, 0x0026, 0x0026, 0x0026, 0x0026, 0x0026, 0x0026, 0x0026 ],
            /* NtQueryFullAttributesFile */ [ 0x0125, 0x0128, 0x012E, 0x0131, 0x0134, 0x0139, 0x013C, 0x013E, 0x013F, 0x0140, 0x0140, 0x0146, 0x0146, 0x0146 ],
            /* NtQueryInformationFile */    [ 0x000F, 0x0010, 0x0011, 0x0011, 0x0011, 0x0011, 0x0011, 0x0011, 0x0011, 0x0011, 0x0011, 0x0011, 0x0011, 0x0011 ],
            /* NtQueryInformationProcess */ [ 0x0017, 0x0018, 0x0019, 0x0019, 0x0019, 0x0019, 0x0019, 0x0019, 0x0019, 0x0019, 0x0019, 0x0019, 0x0019, 0x0019 ],
            /* NtQuerySystemInformation */  [ 0x0034, 0x0035, 0x0036, 0x0036, 0x0036, 0x0036, 0x0036, 0x0036, 0x0036, 0x0036, 0x0036, 0x0036, 0x0036, 0x0036 ],
            /* NtReadFile */                [ 0x0004, 0x0005, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006, 0x0006 ],
            /* NtTerminateProcess */        [ 0x002A, 0x002B, 0x002C, 0x002C, 0x002C, 0x002C, 0x002C, 0x002C, 0x002C, 0x002C, 0x002C, 0x002C, 0x002C, 0x002C ],
            /* NtWriteFile */               [ 0x0006, 0x0007, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008, 0x0008 ],
        ];

        if let crate::system::Version::Official(version) = crate::system::Version::current() {
            if version >= WINDOWS_VERSION_MIN && version <= WINDOWS_VERSION_MAX {
                let mut api_index = 0..SYSCALL_APIS;
                let version_index = version as usize - WINDOWS_VERSION_MIN as usize;

                unsafe {
                    IDS = Some(Ids {
                        close: SYSCALL_IDS[api_index.next().unwrap_unchecked()][version_index],
                        create_file: SYSCALL_IDS[api_index.next().unwrap_unchecked()][version_index],
                        open_process: SYSCALL_IDS[api_index.next().unwrap_unchecked()][version_index],
                        query_full_attributes_file: SYSCALL_IDS[api_index.next().unwrap_unchecked()][version_index],
                        query_information_file: SYSCALL_IDS[api_index.next().unwrap_unchecked()][version_index],
                        query_information_process: SYSCALL_IDS[api_index.next().unwrap_unchecked()][version_index],
                        query_system_information: SYSCALL_IDS[api_index.next().unwrap_unchecked()][version_index],
                        read_file: SYSCALL_IDS[api_index.next().unwrap_unchecked()][version_index],
                        terminate_process: SYSCALL_IDS[api_index.next().unwrap_unchecked()][version_index],
                        write_file: SYSCALL_IDS[api_index.next().unwrap_unchecked()][version_index]
                    });
                }

                return true;
            }
        }

        return false;
    }

    /// Initializes the system call id table with the `Windows XP` values.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn initialize_xp() {
        #[cfg(target_arch = "x86")]
        unsafe {
            IDS = Some(Ids {
                close: 0x19,
                create_file: 0x25,
                open_process: 0x7A,
                query_full_attributes_file: 0x95,
                query_information_file: 0x97,
                query_information_process: 0x9A,
                query_system_information: 0xAD,
                read_file: 0xB7,
                terminate_process: 0x101,
                write_file: 0x112
            });
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            IDS = Some(Ids {
                close: 0xC,
                create_file: 0x52,
                open_process: 0x23,
                query_full_attributes_file: 0xCE,
                query_information_file: 0xE,
                query_information_process: 0x16,
                query_system_information: 0x33,
                read_file: 0x3,
                terminate_process: 0x29,
                write_file: 0x5
            });
        }
    }

    /// Initializes the system call id table with the `Windows Server 2003` values.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn initialize_server_2003() {
        #[cfg(target_arch = "x86")]
        unsafe {
            IDS = Some(Ids {
                close: 0x1B,
                create_file: 0x27,
                open_process: 0x80,
                query_full_attributes_file: 0x9C,
                query_information_file: 0x9E,
                query_information_process: 0xA1,
                query_system_information: 0xB5,
                read_file: 0xBF,
                terminate_process: 0x10A,
                write_file: 0x11C
            });
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            IDS = Some(Ids {
                close: 0xC,
                create_file: 0x52,
                open_process: 0x23,
                query_full_attributes_file: 0xCE,
                query_information_file: 0xE,
                query_information_process: 0x16,
                query_system_information: 0x33,
                read_file: 0x3,
                terminate_process: 0x29,
                write_file: 0x5
            });
        }
    }

    /// Initializes the system call id table with the `Windows Vista` values.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn initialize_vista() {
        #[cfg(target_arch = "x86")]
        unsafe {
            IDS = Some(Ids {
                close: 0x30,
                create_file: 0x3C,
                open_process: 0xC2,
                query_full_attributes_file: 0xDF,
                query_information_file: 0xE1,
                query_information_process: 0xE4,
                query_system_information: 0xF8,
                read_file: 0x102,
                terminate_process: 0x152,
                write_file: 0x167
            });
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            IDS = Some(Ids {
                close: 0xC,
                create_file: 0x52,
                open_process: 0x23,
                query_full_attributes_file: 0x112,
                query_information_file: 0xE,
                query_information_process: 0x16,
                query_system_information: 0x33,
                read_file: 0x3,
                terminate_process: 0x29,
                write_file: 0x5
            });
        }
    }

    /// Initializes the system call id table with the `Windows Vista SP1+` and `Windows Server 2008`
    /// values.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn initialize_vista_sp1_plus_and_server_2008() {
        #[cfg(target_arch = "x86")]
        unsafe {
            IDS = Some(Ids {
                close: 0x30,
                create_file: 0x3C,
                open_process: 0xC2,
                query_full_attributes_file: 0xDF,
                query_information_file: 0xE1,
                query_information_process: 0xE4,
                query_system_information: 0xF8,
                read_file: 0x102,
                terminate_process: 0x14E,
                write_file: 0x163
            });
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            IDS = Some(Ids {
                close: 0xC,
                create_file: 0x52,
                open_process: 0x23,
                query_full_attributes_file: 0x10D,
                query_information_file: 0xE,
                query_information_process: 0x16,
                query_system_information: 0x33,
                read_file: 0x3,
                terminate_process: 0x29,
                write_file: 0x5
            });
        }
    }

    /// Initializes the system call id table with the `Windows Vista Server 2008 R2+` values.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn initialize_server_2008_r2_plus() {
        #[cfg(target_arch = "x86")]
        unsafe {
            IDS = Some(Ids {
                close: 0x30,
                create_file: 0x3C,
                open_process: 0xC2,
                query_full_attributes_file: 0xDF,
                query_information_file: 0xE1,
                query_information_process: 0xE4,
                query_system_information: 0xF8,
                read_file: 0x102,
                terminate_process: 0x14E,
                write_file: 0x163
            });
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            IDS = Some(Ids {
                close: 0xC,
                create_file: 0x52,
                open_process: 0x23,
                query_full_attributes_file: 0x113,
                query_information_file: 0xE,
                query_information_process: 0x16,
                query_system_information: 0x33,
                read_file: 0x3,
                terminate_process: 0x29,
                write_file: 0x5
            });
        }
    }

    /// Initializes the system call id table with the `Windows 7` values.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn initialize_7() {
        #[cfg(target_arch = "x86")]
        unsafe {
            IDS = Some(Ids {
                close: 0x32,
                create_file: 0x42,
                open_process: 0xBE,
                query_full_attributes_file: 0xE4,
                query_information_file: 0xE7,
                query_information_process: 0xEA,
                query_system_information: 0x105,
                read_file: 0x111,
                terminate_process: 0x172,
                write_file: 0x18C
            });
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            IDS = Some(Ids {
                close: 0xC,
                create_file: 0x52,
                open_process: 0x23,
                query_full_attributes_file: 0x113,
                query_information_file: 0xE,
                query_information_process: 0x16,
                query_system_information: 0x33,
                read_file: 0x3,
                terminate_process: 0x29,
                write_file: 0x5
            });
        }
    }

    /// Initializes the system call id table with the `Windows Server 2012` values.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn initialize_server_2012() {
        #[cfg(target_arch = "x86")]
        { /* There is no x86 variant of this Windows version. */ }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            IDS = Some(Ids {
                close: 0xD,
                create_file: 0x53,
                open_process: 0x24,
                query_full_attributes_file: 0x125,
                query_information_file: 0xF,
                query_information_process: 0x17,
                query_system_information: 0x34,
                read_file: 0x4,
                terminate_process: 0x2A,
                write_file: 0x6
            });
        }
    }

    /// Initializes the system call id table with the `Windows Server 2012 R2` values.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn initialize_server_2012_r2() {
        #[cfg(target_arch = "x86")]
        { /* There is no x86 variant of this Windows version. */ }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            IDS = Some(Ids {
                close: 0xE,
                create_file: 0x54,
                open_process: 0x25,
                query_full_attributes_file: 0x128,
                query_information_file: 0x10,
                query_information_process: 0x18,
                query_system_information: 0x35,
                read_file: 0x5,
                terminate_process: 0x2B,
                write_file: 0x7
            });
        }
    }

    /// Initializes the system call id table with the `Windows 8` values.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn initialize_8() {
        #[cfg(target_arch = "x86")]
        unsafe {
            IDS = Some(Ids {
                close: 0x174,
                create_file: 0x163,
                open_process: 0xDD,
                query_full_attributes_file: 0xB6,
                query_information_file: 0xB3,
                query_information_process: 0xB0,
                query_system_information: 0x95,
                read_file: 0x87,
                terminate_process: 0x23,
                write_file: 0x5
            });
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            IDS = Some(Ids {
                close: 0xD,
                create_file: 0x53,
                open_process: 0x24,
                query_full_attributes_file: 0x125,
                query_information_file: 0xF,
                query_information_process: 0x17,
                query_system_information: 0x34,
                read_file: 0x4,
                terminate_process: 0x2A,
                write_file: 0x6
            });
        }
    }

    /// Initializes the system call id table with the `Windows 8.1` values.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn initialize_8_dot_1() {
        #[cfg(target_arch = "x86")]
        unsafe {
            IDS = Some(Ids {
                close: 0x179,
                create_file: 0x168,
                open_process: 0xE0,
                query_full_attributes_file: 0xB9,
                query_information_file: 0xB6,
                query_information_process: 0xB3,
                query_system_information: 0x98,
                read_file: 0x8A,
                terminate_process: 0x23,
                write_file: 0x6
            });
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            IDS = Some(Ids {
                close: 0xE,
                create_file: 0x54,
                open_process: 0x25,
                query_full_attributes_file: 0x128,
                query_information_file: 0x10,
                query_information_process: 0x18,
                query_system_information: 0x35,
                read_file: 0x5,
                terminate_process: 0x2B,
                write_file: 0x7
            });
        }
    }

    /// Initializes the system call id table with the `Windows 10 1507` values.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn initialize_10_1507() {
        #[cfg(target_arch = "x86")]
        unsafe {
            IDS = Some(Ids {
                close: 0x180,
                create_file: 0x16E,
                open_process: 0xE3,
                query_full_attributes_file: 0xBB,
                query_information_file: 0xB8,
                query_information_process: 0xB5,
                query_system_information: 0x9A,
                read_file: 0x8C,
                terminate_process: 0x24,
                write_file: 0x7
            });
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            IDS = Some(Ids {
                close: 0xF,
                create_file: 0x55,
                open_process: 0x26,
                query_full_attributes_file: 0x12E,
                query_information_file: 0x11,
                query_information_process: 0x19,
                query_system_information: 0x36,
                read_file: 0x6,
                terminate_process: 0x2C,
                write_file: 0x8
            });
        }
    }

    /// Initializes the system call id table with the `Windows 10 1511` values.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn initialize_10_1511() {
        #[cfg(target_arch = "x86")]
        unsafe {
            IDS = Some(Ids {
                close: 0x183,
                create_file: 0x170,
                open_process: 0xE3,
                query_full_attributes_file: 0xBB,
                query_information_file: 0xB8,
                query_information_process: 0xB5,
                query_system_information: 0x9A,
                read_file: 0x8C,
                terminate_process: 0x24,
                write_file: 0x7
            });
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            IDS = Some(Ids {
                close: 0xF,
                create_file: 0x55,
                open_process: 0x26,
                query_full_attributes_file: 0x131,
                query_information_file: 0x11,
                query_information_process: 0x19,
                query_system_information: 0x36,
                read_file: 0x6,
                terminate_process: 0x2C,
                write_file: 0x8
            });
        }
    }

    /// Initializes the system call id table with the `Windows 10 1607` values.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn initialize_10_1607() {
        #[cfg(target_arch = "x86")]
        unsafe {
            IDS = Some(Ids {
                close: 0x185,
                create_file: 0x172,
                open_process: 0xE5,
                query_full_attributes_file: 0xBD,
                query_information_file: 0xBA,
                query_information_process: 0xB7,
                query_system_information: 0x9B,
                read_file: 0x8D,
                terminate_process: 0x24,
                write_file: 0x7
            });
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            IDS = Some(Ids {
                close: 0xF,
                create_file: 0x55,
                open_process: 0x26,
                query_full_attributes_file: 0x134,
                query_information_file: 0x11,
                query_information_process: 0x19,
                query_system_information: 0x36,
                read_file: 0x6,
                terminate_process: 0x2C,
                write_file: 0x8
            });
        }
    }

    /// Initializes the system call id table with the `Windows 10 1909` values.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn initialize_10_1909() {
        #[cfg(target_arch = "x86")]
        unsafe {
            IDS = Some(Ids {
                close: 0x18D,
                create_file: 0x178,
                open_process: 0xE9,
                query_full_attributes_file: 0xC0,
                query_information_file: 0xBC,
                query_information_process: 0xB9,
                query_system_information: 0x9D,
                read_file: 0x08E,
                terminate_process: 0x24,
                write_file: 0x7
            });
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            IDS = Some(Ids {
                close: 0xF,
                create_file: 0x55,
                open_process: 0x26,
                query_full_attributes_file: 0x140,
                query_information_file: 0x11,
                query_information_process: 0x19,
                query_system_information: 0x36,
                read_file: 0x6,
                terminate_process: 0x2C,
                write_file: 0x8
            });
        }
    }

    /// Initializes the system call id table with the `Windows 10 2004` values.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn initialize_10_2004() {
        #[cfg(target_arch = "x86")]
        unsafe {
            IDS = Some(Ids {
                close: 0x18E,
                create_file: 0x178,
                open_process: 0xE9,
                query_full_attributes_file: 0xC0,
                query_information_file: 0xBC,
                query_information_process: 0xB9,
                query_system_information: 0x9D,
                read_file: 0x8E,
                terminate_process: 0x24,
                write_file: 0x7
            });
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            IDS = Some(Ids {
                close: 0xF,
                create_file: 0x55,
                open_process: 0x26,
                query_full_attributes_file: 0x146,
                query_information_file: 0x11,
                query_information_process: 0x19,
                query_system_information: 0x36,
                read_file: 0x6,
                terminate_process: 0x2C,
                write_file: 0x8
            });
        }
    }

    /// Initializes the system call id table with the `Windows 10 20H2` values.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn initialize_10_20h2() {
        #[cfg(target_arch = "x86")]
        unsafe {
            IDS = Some(Ids {
                close: 0x18E,
                create_file: 0x178,
                open_process: 0xE9,
                query_full_attributes_file: 0xC0,
                query_information_file: 0xBC,
                query_information_process: 0xB9,
                query_system_information: 0x9D,
                read_file: 0x8E,
                terminate_process: 0x24,
                write_file: 0x7
            });
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            IDS = Some(Ids {
                close: 0xF,
                create_file: 0x55,
                open_process: 0x26,
                query_full_attributes_file: 0x146,
                query_information_file: 0x11,
                query_information_process: 0x19,
                query_system_information: 0x36,
                read_file: 0x6,
                terminate_process: 0x2C,
                write_file: 0x8
            });
        }
    }

    /// Initializes the system call id table with the `Windows 10 21H1` values.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn initialize_10_21h1() {
        #[cfg(target_arch = "x86")]
        unsafe {
            IDS = Some(Ids {
                close: 0x18E,
                create_file: 0x178,
                open_process: 0xE9,
                query_full_attributes_file: 0xC0,
                query_information_file: 0xBC,
                query_information_process: 0xB9,
                query_system_information: 0x9D,
                read_file: 0x8E,
                terminate_process: 0x24,
                write_file: 0x7
            });
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            IDS = Some(Ids {
                close: 0xF,
                create_file: 0x55,
                open_process: 0x26,
                query_full_attributes_file: 0x146,
                query_information_file: 0x11,
                query_information_process: 0x19,
                query_system_information: 0x36,
                read_file: 0x6,
                terminate_process: 0x2C,
                write_file: 0x8
            });
        }
    }
}

// TODO: Add x86 assembly shell code variant and optionally handle WoW64?
#[cfg(target_arch = "x86_64")]
macro_rules! syscall {
    ($id:ident) => { syscall!(#1 $id) };
    ($id:ident, $p1:ident) => { syscall!(#1 $id,
        inout("rcx") $p1 => _,
        out("rdx") _,
        out("r8") _,
        out("r9") _
    ) };
    ($id:ident, $p1:ident, $p2:ident) => { syscall!(#1 $id,
        inout("rcx") $p1 => _,
        inout("rdx") $p2 => _,
        out("r8") _,
        out("r9") _
    ) };
    ($id:ident, $p1:ident, $p2:ident, $p3:ident) => { syscall!(#1 $id,
        inout("rcx") $p1 => _,
        inout("rdx") $p2 => _,
        inout("r8") $p3 => _,
        out("r9") _
    ) };
    ($id:ident, $p1:ident, $p2:ident, $p3:ident, $p4:ident) => { syscall!(#1 $id,
        inout("rcx") $p1 => _,
        inout("rdx") $p2 => _,
        inout("r8") $p3 => _,
        inout("r9") $p4 => _
    ) };
    // More than 4 arguments have to be passed via the stack.
    //
    // Since `asm!` does not allow `in("rsp")` it is passed in and transferred to `rsp` in
    // the assembly code via `in(reg)`.
    //
    // The stack has to be a reference to an array of pointer-sized values and has to begin with
    // `1 (return address) + 4 (shadow space)` pointer-sized values, and is followed by all other
    // arguments that the system call receives.
    ($id:ident, $p1:ident, $p2:ident, $p3:ident, $p4:ident, stack: $stack:ident) => {
        syscall!(#2 $id, "
            xchg rsp, {0}
            mov r10, rcx
            syscall
            xchg rsp, {0}
            ",
            in(reg) $stack,
            inout("rcx") $p1 => _,
            inout("rdx") $p2 => _,
            inout("r8") $p3 => _,
            inout("r9") $p4 => _,
            out("r10") _,
            out("r11") _
        )
    };
    (#1 $id:ident, $($registers:tt)*) => {
        syscall!(#2 $id, "
            mov r10, rcx
            syscall
            ",
            out("r10") _,
            out("r11") _,
            $($registers)*
        )
    };
    (#2 $id:ident, $instructions:expr, $($registers:tt)*) => {{
        let index = match IDS {
            Some(ref ids) => ids.$id as u32,
            None => return Some(crate::error::NtStatusValue::InvalidSystemService.into())
        };

        let result: u32;
        asm!(
            $instructions,
            $($registers)*,
            inout("eax") index => result
        );

        *(&result as *const _ as *const crate::error::NtStatusResult)
    }};
}

/// Official documentation: [ntdll.NtClose](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntclose).
#[allow(non_snake_case)]
#[cfg(winapi = "syscall")]
#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) unsafe fn NtClose(
    object: crate::object::Handle
) -> crate::error::NtStatusResult {
    let object = *(&object as *const _ as *const usize);

    syscall!(close, object)
}

/// Official documentation: [ntdll.NtCreateFile](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile).
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) unsafe fn NtCreateFile(
    handle: *mut crate::object::Handle,
    // Specializations:
    // - `crate::file::DirectoryAccessModes`
    // - `crate::file::FileAccessModes`
    access_modes: u32,
    object_attributes: &crate::object::Attributes,
    io_status_block: *mut crate::io::file::IoStatusBlock,
    allocation_size: Option<&u64>,
    attributes: crate::io::file::Attributes,
    share_modes: crate::io::file::ShareModes,
    // Specializations:
    // - `crate::file::CreationDispositionDirectoryNtDll`
    // - `crate::file::CreationDispositionFileNtDll`
    creation_disposition: u32,
    creation_options: crate::io::file::CreationOptions,
    extended_attributes: Option<&crate::io::file::ntfs::ExtendedAttributesInformation>,
    extended_attributes_size: u32
) -> crate::error::NtStatusResult {
    let stack = &[
        0usize, 0, 0, 0, 0,
        *(&allocation_size as *const _ as *const usize),
        *(&attributes as *const _ as *const u32) as usize,
        *(&share_modes as *const _ as *const u32) as usize,
        creation_disposition as usize,
        *(&creation_options as *const _ as *const u32) as usize,
        *(&extended_attributes as *const _ as *const usize),
        extended_attributes_size as usize
    ];

    syscall!(create_file, handle, access_modes, object_attributes, io_status_block, stack: stack)
}

/// Official documentation: [ntdll.NtOpenProcess](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess).
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) unsafe fn NtOpenProcess(
    handle: *mut crate::object::Handle,
    access_modes: crate::process::AccessModes,
    attributes: &crate::object::Attributes,
    client_id: &crate::process::ClientId
) -> crate::error::NtStatusResult {
    let access_modes = *(&access_modes as *const _ as *const u32) as usize;

    syscall!(open_process, handle, access_modes, attributes, client_id)
}

/// Official documentation: [ntdll.NtQueryFullAttributesFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwqueryfullattributesfile).
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) unsafe fn NtQueryFullAttributesFile(
    attributes: &crate::object::Attributes,
    information: *mut crate::io::file::info::BasicNtDll
) -> crate::error::NtStatusResult {
    syscall!(query_full_attributes_file, attributes, information)
}

/// Official documentation: [ntdll.NtQueryInformationFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryinformationfile).
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) unsafe fn NtQueryInformationFile(
    file: crate::object::Handle,
    io_status_block: *mut crate::io::file::IoStatusBlock,
    buffer: *mut u8,
    buffer_size: u32,
    information: crate::io::file::Information,
) -> crate::error::NtStatusResult {
    let file = *(&file as *const _ as *const usize);

    let stack = &[
        0usize, 0, 0, 0, 0,
        information as usize
    ];

    syscall!(query_information_file, file, io_status_block, buffer, buffer_size, stack: stack)
}

/// Official documentation: [ntdll.NtQueryInformationProcess](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess).
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) unsafe fn NtQueryInformationProcess(
    process: crate::object::Handle,
    information: crate::process::Information,
    buffer: *mut u8,
    buffer_size: u32,
    written_size: *mut u32
) -> crate::error::NtStatusResult {
    let process = *(&process as *const _ as *const usize);
    let information = information as usize;

    let stack = &[
        0usize, 0, 0, 0, 0,
        written_size as usize
    ];

    syscall!(query_information_process, process, information, buffer, buffer_size, stack: stack)
}

/// Official documentation: [ntdll.NtQuerySystemInformation](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation).
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) unsafe fn NtQuerySystemInformation(
    information: crate::system::Information,
    buffer: *const u8,
    buffer_size: u32,
    return_size: Option<&mut u32>
) -> crate::error::NtStatusResult {
    let information = information as usize;
    let return_size = *(&return_size as *const _ as *const usize);

    syscall!(query_system_information, information, buffer, buffer_size, return_size)
}

/// Official documentation [ntdll.NtReadFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntreadfile).
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) unsafe fn NtReadFile(
    file: crate::object::Handle,
    event: Option<crate::object::Handle>,
    _apc_routine: *const u8,
    _apc_context: *const u8,
    io_status_block: *mut crate::io::file::IoStatusBlock,
    buffer: *mut u8,
    buffer_size: u32,
    offset: Option<&u64>,
    _key: Option<&u32>
) -> crate::error::NtStatusResult {
    let file = *(&file as *const _ as *const usize);
    let event = *(&event as *const _ as *const usize);

    let stack = &[
        0usize, 0, 0, 0, 0,
        io_status_block as usize,
        buffer as usize,
        buffer_size as usize,
        *(&offset as *const _ as *const usize),
        *(&_key as *const _ as *const usize)
    ];

    syscall!(read_file, file, event, _apc_routine, _apc_context, stack: stack)
}

/// Official documentation: [ntdll.NtTerminateProcess](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-zwterminateprocess).
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) unsafe fn NtTerminateProcess(
    process: crate::object::Handle,
    exit_code: u32
) -> crate::error::NtStatusResult {
    let process = *(&process as *const _ as *const usize);

    syscall!(terminate_process, process, exit_code)
}

/// Official documentation [ntdll.NtWriteFile](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntwritefile).
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), inline(always))]
pub(crate) unsafe fn NtWriteFile(
    file: crate::object::Handle,
    event: Option<crate::object::Handle>,
    _apc_routine: *const u8,
    _apc_context: *const u8,
    io_status_block: *mut crate::io::file::IoStatusBlock,
    buffer: *const u8,
    buffer_size: u32,
    offset: Option<&u64>,
    _key: Option<&u32>
) -> crate::error::NtStatusResult {
    let file = *(&file as *const _ as *const usize);
    let event = *(&event as *const _ as *const usize);

    let stack = &[
        0usize, 0, 0, 0, 0,
        io_status_block as usize,
        buffer as usize,
        buffer_size as usize,
        *(&offset as *const _ as *const usize),
        *(&_key as *const _ as *const usize)
    ];

    syscall!(write_file, file, event, _apc_routine, _apc_context, stack: stack)
}