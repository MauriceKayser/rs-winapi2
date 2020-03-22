//! Functions to cast buffers to structures.

#[inline(always)]
pub(crate) unsafe fn cast<T>(buffer: &[u8]) -> Option<&T> {
    if core::mem::size_of::<T>() <= buffer.len() {
        Some(&*(buffer as *const _ as *const T))
    } else { None }
}

#[allow(unused)]
#[inline(always)]
pub(crate) unsafe fn cast_mut<T>(buffer: &mut [u8]) -> Option<&mut T> {
    if core::mem::size_of::<T>() <= buffer.len() {
        Some(&mut *(buffer as *mut _ as *mut T))
    } else { None }
}