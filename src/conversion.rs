//! Functions to cast buffers to structures.

// TODO: Set to `pub(crate)` once array lengths support generic parameters (see [#43408](https://github.com/rust-lang/rust/issues/43408)).
/// Casts a large enough byte slice to a generic type reference.
#[cfg_attr(not(debug_assertions), inline(always))]
pub unsafe fn cast<T>(buffer: &[u8], index: usize) -> Option<&T> {
    (core::mem::size_of::<T>() <= buffer.len().checked_sub(index)?)
        .then(|| &*((buffer.as_ptr() as usize + index) as *const T))
}

// TODO: Set to `pub(crate)` once array lengths support generic parameters (see [#43408](https://github.com/rust-lang/rust/issues/43408)).
/// Casts a large enough mutable byte slice to a mutable generic type reference.
#[cfg_attr(not(debug_assertions), inline(always))]
pub unsafe fn cast_mut<T>(buffer: &mut [u8], index: usize) -> Option<&mut T> {
    (core::mem::size_of::<T>() <= buffer.len().checked_sub(index)?)
        .then(|| &mut *((buffer.as_mut_ptr() as usize + index) as *mut T))
}

#[cfg(test)]
mod tests {
    #[repr(C)]
    struct Example {
        f1: u16,
        f2: u8
    }

    #[test]
    fn cast() {
        assert_eq!(core::mem::size_of::<Example>(), 4);

        let buffer = [0, 1, 2];
        assert!(unsafe { super::cast::<Example>(&buffer, 0) }.is_none());

        let buffer = [0, 1, 2, 3];
        assert!(unsafe { super::cast::<Example>(&buffer, 1) }.is_none());
        assert!(unsafe { super::cast::<Example>(&buffer, usize::MAX) }.is_none());
        let s = unsafe { super::cast::<Example>(&buffer, 0).unwrap() };
        assert_eq!(s.f1, 0x0100);
        assert_eq!(s.f2, 0x02);
    }

    #[test]
    fn cast_mut() {
        assert_eq!(core::mem::size_of::<Example>(), 4);

        let mut buffer = [0, 1, 2];
        assert!(unsafe { super::cast_mut::<Example>(&mut buffer, 0) }.is_none());

        let mut buffer = [0, 1, 2, 3];
        assert!(unsafe { super::cast_mut::<Example>(&mut buffer, 1) }.is_none());
        assert!(unsafe { super::cast_mut::<Example>(&mut buffer, usize::MAX) }.is_none());
        let s = unsafe { super::cast_mut::<Example>(&mut buffer, 0).unwrap() };
        assert_eq!(s.f1, 0x0100);
        assert_eq!(s.f2, 0x02);

        s.f2 = 3;
        assert_eq!(&buffer, &[0u8, 1, 3, 3]);
    }
}