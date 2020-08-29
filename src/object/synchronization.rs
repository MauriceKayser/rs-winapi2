//! All object synchronization related Windows types.

/// Stores the necessary information to manipulate an event object.
// TODO: Implement.
pub struct Event(pub(crate) crate::object::Handle);

impl core::ops::Drop for Event {
    #[inline(always)]
    fn drop(&mut self) {
        self.0.clone().close();
    }
}