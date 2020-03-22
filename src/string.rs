//! All string related Windows types.

use alloc::vec::Vec;

/// Borrowed reference to a `String`.
pub struct Str([WideChar]);

impl Str {
    /// Returns a raw pointer to the slice's buffer.
    #[inline(always)]
    pub(crate) fn as_ptr(&self) -> *const WideChar {
        self as *const _ as *const WideChar
    }

    /// Decodes a wide char encoded slice into a `alloc::string::String`.
    #[inline(always)]
    pub fn into_lossy(&self) -> alloc::string::String {
        alloc::string::String::from_utf16_lossy(self.into())
    }

    /// Returns the amount of referenced wide characters.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl<'a> core::convert::From<&'a [WideChar]> for &'a Str {
    #[inline(always)]
    fn from(value: &'a [WideChar]) -> Self {
        unsafe { &*(value as *const [WideChar] as *const Str) }
    }
}

impl<'a> core::convert::Into<&'a [WideChar]> for &'a Str {
    #[inline(always)]
    fn into(self) -> &'a [WideChar] {
        unsafe { &*(self as *const Str as *const [WideChar]) }
    }
}

/// Owns a wide char encoded string.
pub struct String(Vec<WideChar>);

impl String {
    /// Returns a raw pointer to the slice's buffer.
    #[inline(always)]
    pub(crate) fn as_ptr(&self) -> *const WideChar {
        self.as_ref().as_ptr()
    }

    /// Decodes a wide char encoded slice into a `alloc::string::String`.
    #[inline(always)]
    pub fn into_lossy(&self) -> alloc::string::String {
        self.as_ref().into_lossy()
    }

    /// Returns the amount of stored wide characters.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.as_ref().len()
    }
}

impl core::convert::From<&str> for String {
    #[inline(always)]
    fn from(value: &str) -> Self {
        Self(value.encode_utf16().collect())
    }
}

impl core::convert::From<&Str> for String {
    #[inline(always)]
    fn from(value: &Str) -> Self {
        Self(Vec::from(&value.0))
    }
}

impl core::convert::AsRef<Str> for String {
    #[inline(always)]
    fn as_ref(&self) -> &Str {
        self
    }
}

impl core::ops::Deref for String {
    type Target = Str;

    #[inline(always)]
    fn deref(&self) -> &Str {
        &self[..]
    }
}

impl core::ops::Index<core::ops::RangeFull> for String {
    type Output = Str;

    #[inline(always)]
    fn index(&self, _index: core::ops::RangeFull) -> &Str {
        core::convert::From::<&[WideChar]>::from(self.0.as_slice())
        // Str::from(self.0.as_slice())
    }
}

/// Official documentation: [UNICODE_STRING struct](https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_unicode_string).
#[repr(C)]
pub struct StringW<'a> {
    length: u16,
    capacity: u16,
    buffer: *const WideChar,
    _phantom: core::marker::PhantomData<&'a WideChar>
}

impl<'a> core::convert::Into<&'a Str> for &'a StringW<'a> {
    #[inline(always)]
    fn into(self) -> &'a Str {
        core::convert::From::<&[WideChar]>::from(unsafe { core::slice::from_raw_parts(
            self.buffer,
            self.length as usize / core::mem::size_of::<WideChar>()
        ) })
    }
}

/// Official documentation: [Working with Strings](https://docs.microsoft.com/en-us/windows/win32/learnwin32/working-with-strings).
///
/// Strings on Windows are encoded in WTF-16.
pub type WideChar = u16;