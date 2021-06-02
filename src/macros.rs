/// Returns the offset of a field in a struct.
///
/// **WARNING**: Using this on structs without `#[repr(C)]` or `#[repr(packed)]` might yield
/// unexpected results!
macro_rules! offset_of {
    ($ty:ty, $field:ident) => {
        &(*(0 as *const $ty)).$field as *const _ as usize
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn offset_of_repr_c() {
        #[repr(C)]
        struct Test {
            at_c_0: u8,
            at_c_1: u8,
            at_c_2: u8,
            at_c_4: u16
        }

        assert_eq!(unsafe { offset_of!(Test, at_c_0) }, 0);
        assert_eq!(unsafe { offset_of!(Test, at_c_1) }, 1);
        assert_eq!(unsafe { offset_of!(Test, at_c_2) }, 2);
        assert_eq!(unsafe { offset_of!(Test, at_c_4) }, 4);
    }

    #[test]
    fn offset_of_repr_packed() {
        #[repr(packed)]
        struct Test {
            at_packed_0: u8,
            at_packed_1: u8,
            at_packed_2: u8,
            at_packed_3: u16
        }

        assert_eq!(unsafe { offset_of!(Test, at_packed_0) }, 0);
        assert_eq!(unsafe { offset_of!(Test, at_packed_1) }, 1);
        assert_eq!(unsafe { offset_of!(Test, at_packed_2) }, 2);
        assert_eq!(unsafe { offset_of!(Test, at_packed_3) }, 3);
    }

    #[test]
    fn offset_of_repr_rust() {
        struct Test {
            at_rust_2: u8,
            at_rust_3: u8,
            at_rust_4: u8,
            at_rust_0: u16
        }

        assert_eq!(unsafe { offset_of!(Test, at_rust_2) }, 2);
        assert_eq!(unsafe { offset_of!(Test, at_rust_3) }, 3);
        assert_eq!(unsafe { offset_of!(Test, at_rust_4) }, 4);
        assert_eq!(unsafe { offset_of!(Test, at_rust_0) }, 0);
    }
}