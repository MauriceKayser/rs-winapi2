//! All string related Windows types.

use alloc::vec::Vec;

/// Generic string comparison functions.
pub trait ImplString<T> {
    /// Returns `true` if this string slice ends with the given sub string.
    fn ends_with(&self, sub: T) -> bool;

    /// Returns `true` if this string slice starts with with the given sub string.
    fn starts_with(&self, sub: T) -> bool;
}

/// Borrowed reference to an ANSI encoded string.
///
/// Warning: Comparing this to a Rust `str` just works for the ASCII range.
#[derive(Eq, PartialEq)]
pub struct AnsiStr([AnsiChar]);

impl AnsiStr {
    /// Returns a `AnsiChar` slice of this `AnsiStr`'s contents.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn as_chars(&self) -> &[AnsiChar] {
        &self.0
    }

    /// Returns a mutable `AnsiChar` slice of this `AnsiStr`'s contents.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn as_chars_mut(&mut self) -> &mut [AnsiChar] {
        &mut self.0
    }

    /// Returns a mutable raw pointer to the slice's buffer.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn as_mut_ptr(&mut self) -> *mut AnsiChar {
        self.0.as_mut_ptr()
    }

    /// Returns a raw pointer to the slice's buffer.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn as_ptr(&self) -> *const AnsiChar {
        self.0.as_ptr()
    }

    /// Decodes a ANSI char encoded slice into a `alloc::string::String`.
    ///
    /// All characters outside of the ASCII range are converted to `char::REPLACEMENT_CHARACTER`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn into_lossy(&self) -> alloc::borrow::Cow<str> {
        let mut s: Option<alloc::string::String> = None;

        for (i, c) in self.0.iter().enumerate() {
            if let Some(s) = &mut s {
                s.push(if *c <= 0x7F { char::from(*c) } else { char::REPLACEMENT_CHARACTER });
            } else if *c > 0x7F {
                s = Some(alloc::string::String::with_capacity(self.0.len()));
                let s = unsafe { s.as_mut().unwrap_unchecked() };

                // Copy over the previous ASCII encoded data.
                unsafe { s.as_mut_vec().extend_from_slice(&self.0[..i]); }
                // Copy over the current non-ASCII character.
                s.push(char::REPLACEMENT_CHARACTER);
            } else {
                // Best case scenario: No heap allocation necessary.
            }
        }

        match s {
            Some(s) => alloc::borrow::Cow::Owned(s),
            None => alloc::borrow::Cow::Borrowed(unsafe { core::str::from_utf8_unchecked(&self.0) })
        }
    }

    /// Returns `true` if `self` has a length of zero bytes.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the amount of referenced wide characters.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns a possibly zero-terminated string reference from a zero-terminated string pointer.
    /// If `max_length` is reached before a zero-terminator is found, the returned string will not
    /// contain a zero-terminator.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub unsafe fn from_terminated<'a>(
        terminated_string: *const AnsiChar,
        max_length: Option<core::num::NonZeroUsize>,
        exclude_zero_terminator: bool
    ) -> &'a Self {
        Self::from_terminated_mut(terminated_string as _, max_length, exclude_zero_terminator)
    }

    /// Returns a possibly zero-terminated string reference from a zero-terminated string pointer.
    /// If `max_length` is reached before a zero-terminator is found, the returned string will not
    /// contain a zero-terminator.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(crate) unsafe fn from_terminated_with_offset<'a>(
        terminated_string: *const AnsiChar,
        offset: usize,
        max_length: Option<core::num::NonZeroUsize>,
        exclude_zero_terminator: bool
    ) -> &'a Self {
        Self::from_terminated_mut(
            (terminated_string as usize).unchecked_add(offset) as _,
            max_length,
            exclude_zero_terminator
        )
    }

    /// Returns a possibly zero-terminated, mutable string reference from a zero-terminated string
    /// pointer. If `max_length` is reached before a zero-terminator is found, the returned string
    /// will not contain a zero-terminator.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub unsafe fn from_terminated_mut<'a>(
        terminated_string: *mut AnsiChar,
        max_length: Option<core::num::NonZeroUsize>,
        exclude_zero_terminator: bool
    ) -> &'a mut Self {
        core::convert::From::<&mut [AnsiChar]>::from(Str::from_terminated_mut_t(
            terminated_string as _, max_length, exclude_zero_terminator
        ))
    }
}

impl ImplString<&str> for AnsiStr {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn ends_with(&self, sub: &str) -> bool {
        if self.len() < sub.len() { return false; }

        for (c1, c2) in sub.chars().rev().zip(self.0.iter().rev()) {
            // This only works for the ASCII range.
            if c1 as u32 != *c2 as u32 {
                return false;
            }
        }

        true
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn starts_with(&self, sub: &str) -> bool {
        if self.len() < sub.len() { return false; }

        for (c1, c2) in sub.chars().zip(self.0.iter()) {
            // This only works for the ASCII range.
            if c1 as u32 != *c2 as u32 {
                return false;
            }
        }

        true
    }
}

impl ImplString<&Self> for AnsiStr {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn ends_with(&self, sub: &Self) -> bool {
        if self.as_ptr() == sub.as_ptr() { return true; }
        if self.len() < sub.len() { return false; }

        self.0[self.len() - sub.len()..] == sub.0
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn starts_with(&self, sub: &Self) -> bool {
        if self.as_ptr() == sub.as_ptr() { return true; }
        if self.len() < sub.len() { return false; }

        self.0[..sub.len()] == sub.0
    }
}

impl core::cmp::PartialEq<str> for AnsiStr {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn eq(&self, other: &str) -> bool {
        if self.len() != other.len() { return false; }

        self.starts_with(other)
    }
}

impl core::cmp::PartialEq<&str> for AnsiStr {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn eq(&self, other: &&str) -> bool {
        self.eq(*other)
    }
}

impl<'a> core::convert::From<&'a [AnsiChar]> for &'a AnsiStr {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(value: &'a [AnsiChar]) -> Self {
        unsafe { &*(value as *const [AnsiChar] as *const AnsiStr) }
    }
}

impl<'a> core::convert::From<&'a mut [AnsiChar]> for &'a mut AnsiStr {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(value: &'a mut [AnsiChar]) -> Self {
        unsafe { &mut *(value as *mut [AnsiChar] as *mut AnsiStr) }
    }
}

impl<'a> core::convert::Into<&'a [AnsiChar]> for &'a AnsiStr {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn into(self) -> &'a [AnsiChar] {
        unsafe { &*(self as *const AnsiStr as *const [AnsiChar]) }
    }
}

impl<'a> core::convert::Into<&'a mut [AnsiChar]> for &'a mut AnsiStr {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn into(self) -> &'a mut [AnsiChar] {
        unsafe { &mut *(self as *mut AnsiStr as *mut [AnsiChar]) }
    }
}

impl core::fmt::Debug for AnsiStr {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_fmt(format_args!("{:?}", self.into_lossy()))
    }
}

impl core::fmt::Display for AnsiStr {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(&self.into_lossy())
    }
}

impl core::ops::Index<usize> for AnsiStr {
    type Output = AnsiChar;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl core::ops::Index<core::ops::Range<usize>> for AnsiStr {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index(&self, index: core::ops::Range<usize>) -> &Self::Output {
        core::convert::From::from(&self.0[index])
    }
}

impl core::ops::Index<core::ops::RangeFrom<usize>> for AnsiStr {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index(&self, index: core::ops::RangeFrom<usize>) -> &Self::Output {
        core::convert::From::from(&self.0[index])
    }
}

impl core::ops::Index<core::ops::RangeFull> for AnsiStr {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index(&self, index: core::ops::RangeFull) -> &Self::Output {
        core::convert::From::from(&self.0[index])
    }
}

impl core::ops::Index<core::ops::RangeInclusive<usize>> for AnsiStr {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index(&self, index: core::ops::RangeInclusive<usize>) -> &Self::Output {
        core::convert::From::from(&self.0[index])
    }
}

impl core::ops::Index<core::ops::RangeTo<usize>> for AnsiStr {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index(&self, index: core::ops::RangeTo<usize>) -> &Self::Output {
        core::convert::From::from(&self.0[index])
    }
}

impl core::ops::Index<core::ops::RangeToInclusive<usize>> for AnsiStr {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index(&self, index: core::ops::RangeToInclusive<usize>) -> &Self::Output {
        core::convert::From::from(&self.0[index])
    }
}

impl core::ops::IndexMut<usize> for AnsiStr {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl core::ops::IndexMut<core::ops::Range<usize>> for AnsiStr {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index_mut(&mut self, index: core::ops::Range<usize>) -> &mut Self::Output {
        core::convert::From::from(&mut self.0[index])
    }
}

impl core::ops::IndexMut<core::ops::RangeFrom<usize>> for AnsiStr {
    fn index_mut(&mut self, index: core::ops::RangeFrom<usize>) -> &mut Self::Output {
        core::convert::From::from(&mut self.0[index])
    }
}

impl core::ops::IndexMut<core::ops::RangeFull> for AnsiStr {
    fn index_mut(&mut self, index: core::ops::RangeFull) -> &mut Self::Output {
        core::convert::From::from(&mut self.0[index])
    }
}

impl core::ops::IndexMut<core::ops::RangeInclusive<usize>> for AnsiStr {
    fn index_mut(&mut self, index: core::ops::RangeInclusive<usize>) -> &mut Self::Output {
        core::convert::From::from(&mut self.0[index])
    }
}

impl core::ops::IndexMut<core::ops::RangeTo<usize>> for AnsiStr {
    fn index_mut(&mut self, index: core::ops::RangeTo<usize>) -> &mut Self::Output {
        core::convert::From::from(&mut self.0[index])
    }
}

impl core::ops::IndexMut<core::ops::RangeToInclusive<usize>> for AnsiStr {
    fn index_mut(&mut self, index: core::ops::RangeToInclusive<usize>) -> &mut Self::Output {
        core::convert::From::from(&mut self.0[index])
    }
}

/// Borrowed reference to a `String`.
#[derive(Eq, PartialEq)]
pub struct Str([WideChar]);

impl Str {
    /// Returns a `WideChar` slice of this `Str`'s contents.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn as_chars(&self) -> &[WideChar] {
        &self.0
    }

    /// Returns a mutable `WideChar` slice of this `Str`'s contents.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn as_chars_mut(&mut self) -> &mut [WideChar] {
        &mut self.0
    }

    /// Returns a mutable raw pointer to the slice's buffer.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn as_mut_ptr(&mut self) -> *mut WideChar {
        self.0.as_mut_ptr()
    }

    /// Returns a raw pointer to the slice's buffer.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn as_ptr(&self) -> *const WideChar {
        self.0.as_ptr()
    }

    /// Decodes a wide char encoded slice into a `alloc::string::String`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn into_lossy(&self) -> alloc::string::String {
        alloc::string::String::from_utf16_lossy(self.into())
    }

    /// Returns `true` if `self` has a length of zero bytes.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the amount of referenced wide characters.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns a possibly zero-terminated string reference from a zero-terminated string pointer.
    /// If `max_length` is reached before a zero-terminator is found, the returned string will not
    /// contain a zero-terminator.
    pub unsafe fn from_terminated<'a>(
        terminated_string: *const WideChar,
        max_length: Option<core::num::NonZeroUsize>,
        exclude_zero_terminator: bool
    ) -> &'a Self {
        Self::from_terminated_mut(terminated_string as _, max_length, exclude_zero_terminator)
    }

    /// Returns a possibly zero-terminated, mutable string reference from a zero-terminated string
    /// pointer. If `max_length` is reached before a zero-terminator is found, the returned string
    /// will not contain a zero-terminator.
    pub unsafe fn from_terminated_mut<'a>(
        terminated_string: *mut WideChar,
        max_length: Option<core::num::NonZeroUsize>,
        exclude_zero_terminator: bool
    ) -> &'a mut Self {
        core::convert::From::<&mut [WideChar]>::from(Self::from_terminated_mut_t(
            terminated_string as _, max_length, exclude_zero_terminator
        ))
    }

    /// Returns a possibly zero-terminated, mutable string reference from a zero-terminated string
    /// pointer. If `max_length` is reached before a zero-terminator is found, the returned string
    /// will not contain a zero-terminator.
    unsafe fn from_terminated_mut_t<'a, T: PartialEq + From<u8>>(
        terminated_string: *mut T,
        max_length: Option<core::num::NonZeroUsize>,
        exclude_zero_terminator: bool
    ) -> &'a mut [T] {
        let mut count = 0;

        loop {
            if terminated_string.add(count).read() == core::convert::From::<u8>::from(0) {
                return core::slice::from_raw_parts_mut(
                    terminated_string,
                    count + (!exclude_zero_terminator) as usize
                );
            }

            count += 1;

            // Return early if `max_length` is reached.
            if let Some(max_length) = max_length {
                if max_length.get() == count {
                    return core::slice::from_raw_parts_mut(
                        terminated_string, count as usize
                    );
                }
            }
        }
    }
}

impl ImplString<&str> for Str {
    fn ends_with(&self, sub: &str) -> bool {
        if self.len() < sub.len() { return false; }

        let mut index = self.len();
        for c in sub.chars().rev() {
            let mut utf16 = [0; 2];
            let utf16 = c.encode_utf16(&mut utf16);

            index -= utf16.len();

            match utf16.len() {
                1 => if self.0[index] != utf16[0] { return false; },

                2 => if self.0[index] != utf16[0] || self.0[index + 1] != utf16[1] { return false; },

                _ => return false
            }
        }

        true
    }

    fn starts_with(&self, sub: &str) -> bool {
        if self.len() < sub.len() { return false; }

        let mut index = 0;
        for c in sub.chars() {
            let mut utf16 = [0; 2];
            let utf16 = c.encode_utf16(&mut utf16);

            match utf16.len() {
                1 => if self.0[index] != utf16[0] { return false; },

                2 => if self.0[index] != utf16[0] || self.0[index + 1] != utf16[1] { return false; },

                _ => return false
            }

            index += utf16.len();
        }

        true
    }
}

impl ImplString<&Self> for Str {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn ends_with(&self, sub: &Self) -> bool {
        if self.as_ptr() == sub.as_ptr() { return true; }
        if self.len() < sub.len() { return false; }

        self.0[self.len() - sub.len()..] == sub.0
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn starts_with(&self, sub: &Self) -> bool {
        if self.as_ptr() == sub.as_ptr() { return true; }
        if self.len() < sub.len() { return false; }

        self.0[..sub.len()] == sub.0
    }
}

impl ImplString<&String> for Str {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn ends_with(&self, sub: &String) -> bool {
        self.ends_with(sub.as_ref())
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn starts_with(&self, sub: &String) -> bool {
        self.starts_with(sub.as_ref())
    }
}

impl core::cmp::PartialEq<str> for Str {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn eq(&self, other: &str) -> bool {
        if self.len() != other.len() { return false; }

        self.starts_with(other)
    }
}

impl core::cmp::PartialEq<&str> for Str {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn eq(&self, other: &&str) -> bool {
        self.eq(*other)
    }
}

impl<'a> core::convert::From<&'a [WideChar]> for &'a Str {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(value: &'a [WideChar]) -> Self {
        unsafe { &*(value as *const [WideChar] as *const Str) }
    }
}

impl<'a> core::convert::From<&'a mut [WideChar]> for &'a mut Str {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(value: &'a mut [WideChar]) -> Self {
        unsafe { &mut *(value as *mut [WideChar] as *mut Str) }
    }
}

impl<'a> core::convert::Into<&'a [WideChar]> for &'a Str {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn into(self) -> &'a [WideChar] {
        unsafe { &*(self as *const Str as *const [WideChar]) }
    }
}

impl<'a> core::convert::Into<&'a mut [WideChar]> for &'a mut Str {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn into(self) -> &'a mut [WideChar] {
        unsafe { &mut *(self as *mut Str as *mut [WideChar]) }
    }
}

impl core::fmt::Debug for Str {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_fmt(format_args!("{:?}", self.into_lossy()))
    }
}

impl core::fmt::Display for Str {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(&self.into_lossy())
    }
}

impl core::ops::Index<usize> for Str {
    type Output = WideChar;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl core::ops::Index<core::ops::Range<usize>> for Str {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index(&self, index: core::ops::Range<usize>) -> &Self::Output {
        core::convert::From::from(&self.0[index])
    }
}

impl core::ops::Index<core::ops::RangeFrom<usize>> for Str {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index(&self, index: core::ops::RangeFrom<usize>) -> &Self::Output {
        core::convert::From::from(&self.0[index])
    }
}

impl core::ops::Index<core::ops::RangeFull> for Str {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index(&self, index: core::ops::RangeFull) -> &Self::Output {
        core::convert::From::from(&self.0[index])
    }
}

impl core::ops::Index<core::ops::RangeInclusive<usize>> for Str {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index(&self, index: core::ops::RangeInclusive<usize>) -> &Self::Output {
        core::convert::From::from(&self.0[index])
    }
}

impl core::ops::Index<core::ops::RangeTo<usize>> for Str {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index(&self, index: core::ops::RangeTo<usize>) -> &Self::Output {
        core::convert::From::from(&self.0[index])
    }
}

impl core::ops::Index<core::ops::RangeToInclusive<usize>> for Str {
    type Output = Self;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index(&self, index: core::ops::RangeToInclusive<usize>) -> &Self::Output {
        core::convert::From::from(&self.0[index])
    }
}

impl core::ops::IndexMut<usize> for Str {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl core::ops::IndexMut<core::ops::Range<usize>> for Str {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index_mut(&mut self, index: core::ops::Range<usize>) -> &mut Self::Output {
        core::convert::From::from(&mut self.0[index])
    }
}

impl core::ops::IndexMut<core::ops::RangeFrom<usize>> for Str {
    fn index_mut(&mut self, index: core::ops::RangeFrom<usize>) -> &mut Self::Output {
        core::convert::From::from(&mut self.0[index])
    }
}

impl core::ops::IndexMut<core::ops::RangeFull> for Str {
    fn index_mut(&mut self, index: core::ops::RangeFull) -> &mut Self::Output {
        core::convert::From::from(&mut self.0[index])
    }
}

impl core::ops::IndexMut<core::ops::RangeInclusive<usize>> for Str {
    fn index_mut(&mut self, index: core::ops::RangeInclusive<usize>) -> &mut Self::Output {
        core::convert::From::from(&mut self.0[index])
    }
}

impl core::ops::IndexMut<core::ops::RangeTo<usize>> for Str {
    fn index_mut(&mut self, index: core::ops::RangeTo<usize>) -> &mut Self::Output {
        core::convert::From::from(&mut self.0[index])
    }
}

impl core::ops::IndexMut<core::ops::RangeToInclusive<usize>> for Str {
    fn index_mut(&mut self, index: core::ops::RangeToInclusive<usize>) -> &mut Self::Output {
        core::convert::From::from(&mut self.0[index])
    }
}

/// Owns a wide char encoded string.
pub struct String(Vec<WideChar>);

impl String {
    /// Creates a new empty `String`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Creates a new empty `String` with a particular capacity.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    /// Returns a `WideChar` slice of this `String`'s contents.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn as_chars(&self) -> &[WideChar] {
        &self.0
    }

    /// Returns a mutable `WideChar` slice of this `String`'s contents.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn as_chars_mut(&mut self) -> &mut [WideChar] {
        &mut self.0
    }

    /// Returns a mutable raw pointer to the slice's buffer.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn as_mut_ptr(&mut self) -> *mut WideChar {
        self.as_mut().as_mut_ptr()
    }

    /// Returns a raw pointer to the slice's buffer.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn as_ptr(&self) -> *const WideChar {
        self.as_ref().as_ptr()
    }

    /// Decodes a wide char encoded slice into a `alloc::string::String`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn into_lossy(&self) -> alloc::string::String {
        self.as_ref().into_lossy()
    }

    /// Returns `true` if `self` has a length of zero bytes.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of wide characters the `String` can hold without reallocating.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn capacity(&self) -> usize {
        self.0.capacity()
    }

    /// Returns the amount of referenced wide characters.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Truncates this `String`, removing all contents.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// Ensures that this `String`'s capacity is at least `additional` wide characters larger than
    /// its length.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn reserve(&mut self, additional: usize) {
        self.0.reserve(additional)
    }

    /// Ensures that this `String`'s capacity is `additional` wide characters larger than its
    /// length.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn reserve_exact(&mut self, additional: usize) {
        self.0.reserve_exact(additional)
    }

    /// Forces the length of the string to `new_len`.
    pub unsafe fn set_len(&mut self, new_len: usize) {
        self.0.set_len(new_len)
    }

    /// Shrinks the capacity of this `String` to match its length.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn shrink_to_fit(&mut self) {
        self.0.shrink_to_fit()
    }

    /// Shortens this `String` to the specified length.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn truncate(&mut self, new_len: usize) {
        self.0.truncate(new_len);
    }

    /// Inserts a wide character into this `String` at a wide character position.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn insert(&mut self, idx: usize, ch: WideChar) {
        self.0.insert(idx, ch)
    }

    /// Inserts a `char` into this `String` at a wide character position.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn insert_char(&mut self, idx: usize, ch: char) {
        let mut utf16 = [0; 2];
        let utf16 = ch.encode_utf16(&mut utf16);
        self.insert_str(idx, utf16.as_ref().into());
    }

    /// Inserts a string slice into this `String` at a wide character position.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn insert_str(&mut self, idx: usize, string: &Str) {
        let len = self.len();
        let amt = string.len();
        self.0.reserve(amt);

        unsafe {
            core::ptr::copy(
                self.0.as_ptr().add(idx),
                self.0.as_mut_ptr().add(idx + amt),
                len - idx
            );
            core::ptr::copy(
                string.as_ptr(),
                self.0.as_mut_ptr().add(idx),
                amt
            );
            self.0.set_len(len + amt);
        }
    }

    /// Inserts a string slice into this `String` at a wide character position.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn insert_utf8(&mut self, idx: usize, string: &str) {
        let utf16: Vec<WideChar> = string.encode_utf16().collect();
        self.insert_str(idx, utf16.as_slice().into())
    }

    /// Appends the given wide character to the end of this `String`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn push(&mut self, ch: WideChar) {
        self.0.push(ch);
    }

    /// Appends the given `char` to the end of this `String`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn push_char(&mut self, ch: char) {
        let mut utf16 = [0; 2];
        let utf16 = ch.encode_utf16(&mut utf16);
        self.push_str(utf16.as_ref().into());
    }

    /// Appends a given string slice onto the end of this `String`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn push_str(&mut self, string: &Str) {
        self.0.extend_from_slice(string.into())
    }

    /// Appends a given string slice onto the end of this `String`.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn push_utf8(&mut self, string: &str) {
        self.0.extend(string.encode_utf16())
    }

    /// Removes the last character from the string buffer and returns it.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn pop(&mut self) -> Option<WideChar> {
        self.0.pop()
    }

    /// Removes a wide character from this `String` at a wide character position and returns it.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn remove(&mut self, idx: usize) -> WideChar {
        self.0.remove(idx)
    }
}

impl ImplString<&str> for String {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn ends_with(&self, sub: &str) -> bool {
        self.as_ref().ends_with(sub)
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn starts_with(&self, sub: &str) -> bool {
        self.as_ref().starts_with(sub)
    }
}

impl ImplString<&Str> for String {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn ends_with(&self, sub: &Str) -> bool {
        self.as_ref().ends_with(sub)
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn starts_with(&self, sub: &Str) -> bool {
        self.as_ref().starts_with(sub)
    }
}

impl ImplString<&String> for String {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn ends_with(&self, sub: &Self) -> bool {
        self.as_ref().ends_with(sub.as_ref())
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn starts_with(&self, sub: &Self) -> bool {
        self.as_ref().starts_with(sub.as_ref())
    }
}

impl core::cmp::PartialEq<Str> for String {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn eq(&self, other: &Str) -> bool {
        self.as_ref().eq(other)
    }
}

impl core::cmp::PartialEq<str> for String {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn eq(&self, other: &str) -> bool {
        self.as_ref().eq(other)
    }
}

impl core::cmp::PartialEq<&str> for String {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn eq(&self, other: &&str) -> bool {
        self.as_ref().eq(other)
    }
}

impl core::convert::From<&str> for String {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(value: &str) -> Self {
        Self(value.encode_utf16().collect())
    }
}

impl core::convert::From<&Str> for String {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(value: &Str) -> Self {
        Self(Vec::from(&value.0))
    }
}

impl core::convert::AsRef<Str> for String {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn as_ref(&self) -> &Str {
        self
    }
}

impl core::convert::AsMut<Str> for String {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn as_mut(&mut self) -> &mut Str {
        self
    }
}

impl core::fmt::Debug for String {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_fmt(format_args!("{:?}", self.into_lossy()))
    }
}

impl core::fmt::Display for String {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(&self.as_ref().into_lossy())
    }
}

impl core::ops::Deref for String {
    type Target = Str;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn deref(&self) -> &Str {
        &self[..]
    }
}

impl core::ops::DerefMut for String {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn deref_mut(&mut self) -> &mut Str {
        &mut self[..]
    }
}

impl core::ops::Index<usize> for String {
    type Output = WideChar;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl core::ops::Index<core::ops::Range<usize>> for String {
    type Output = Str;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index(&self, index: core::ops::Range<usize>) -> &Self::Output {
        core::convert::From::from(&self.0[index])
    }
}

impl core::ops::Index<core::ops::RangeFrom<usize>> for String {
    type Output = Str;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index(&self, index: core::ops::RangeFrom<usize>) -> &Self::Output {
        core::convert::From::from(&self.0[index])
    }
}

impl core::ops::Index<core::ops::RangeFull> for String {
    type Output = Str;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index(&self, index: core::ops::RangeFull) -> &Self::Output {
        core::convert::From::from(&self.0[index])
    }
}

impl core::ops::Index<core::ops::RangeInclusive<usize>> for String {
    type Output = Str;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index(&self, index: core::ops::RangeInclusive<usize>) -> &Self::Output {
        core::convert::From::from(&self.0[index])
    }
}

impl core::ops::Index<core::ops::RangeTo<usize>> for String {
    type Output = Str;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index(&self, index: core::ops::RangeTo<usize>) -> &Self::Output {
        core::convert::From::from(&self.0[index])
    }
}

impl core::ops::Index<core::ops::RangeToInclusive<usize>> for String {
    type Output = Str;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index(&self, index: core::ops::RangeToInclusive<usize>) -> &Self::Output {
        core::convert::From::from(&self.0[index])
    }
}

impl core::ops::IndexMut<usize> for String {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl core::ops::IndexMut<core::ops::Range<usize>> for String {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index_mut(&mut self, index: core::ops::Range<usize>) -> &mut Self::Output {
        core::convert::From::from(&mut self.0[index])
    }
}

impl core::ops::IndexMut<core::ops::RangeFrom<usize>> for String {
    fn index_mut(&mut self, index: core::ops::RangeFrom<usize>) -> &mut Self::Output {
        core::convert::From::from(&mut self.0[index])
    }
}

impl core::ops::IndexMut<core::ops::RangeFull> for String {
    fn index_mut(&mut self, index: core::ops::RangeFull) -> &mut Self::Output {
        core::convert::From::from(&mut self.0[index])
    }
}

impl core::ops::IndexMut<core::ops::RangeInclusive<usize>> for String {
    fn index_mut(&mut self, index: core::ops::RangeInclusive<usize>) -> &mut Self::Output {
        core::convert::From::from(&mut self.0[index])
    }
}

impl core::ops::IndexMut<core::ops::RangeTo<usize>> for String {
    fn index_mut(&mut self, index: core::ops::RangeTo<usize>) -> &mut Self::Output {
        core::convert::From::from(&mut self.0[index])
    }
}

impl core::ops::IndexMut<core::ops::RangeToInclusive<usize>> for String {
    fn index_mut(&mut self, index: core::ops::RangeToInclusive<usize>) -> &mut Self::Output {
        core::convert::From::from(&mut self.0[index])
    }
}

/// Official documentation: [ANSI_STRING struct](https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-string).
#[repr(C)]
pub struct StringA<'a> {
    length: u16,
    capacity: u16,
    buffer: *const AnsiChar,
    _phantom: core::marker::PhantomData<&'a AnsiChar>
}

impl<'a> StringA<'a> {
    /// Returns the string buffer with all its capacity.
    ///
    /// If only the actual string data is wanted, use `StringA.into()` instead.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn buffer(&self) -> &AnsiStr {
        core::convert::From::<&[AnsiChar]>::from(unsafe { core::slice::from_raw_parts(
            self.buffer,
            self.capacity as usize / core::mem::size_of::<AnsiChar>()
        ) })
    }
}

impl<'a> core::convert::AsRef<AnsiStr> for StringA<'a> {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn as_ref(&self) -> &AnsiStr {
        core::convert::From::<&[AnsiChar]>::from(unsafe { core::slice::from_raw_parts(
            self.buffer,
            self.length as usize / core::mem::size_of::<AnsiChar>()
        ) })
    }
}

/// `length` will not contain the trailing zero-terminator, if `value` has one.
impl<'a> core::convert::From<&'a AnsiStr> for StringA<'a> {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(value: &'a AnsiStr) -> Self {
        Self {
            length: (
                (value.0.len() * core::mem::size_of::<AnsiChar>()) -
                (value.0.last().cloned() == Some(0)) as usize * core::mem::size_of::<AnsiChar>()
            ) as u16,
            capacity: (value.0.len() * core::mem::size_of::<AnsiChar>()) as u16,
            buffer: value.as_ptr(),
            _phantom: core::marker::PhantomData
        }
    }
}

/// Official documentation: [UNICODE_STRING struct](https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_unicode_string).
#[repr(C)]
pub struct StringW<'a> {
    length: u16,
    capacity: u16,
    pub(crate) buffer: *const WideChar,
    _phantom: core::marker::PhantomData<&'a WideChar>
}

impl<'a> StringW<'a> {
    /// Returns the string buffer with all its capacity.
    ///
    /// If only the actual string data is wanted, use `StringW.into()` instead.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn buffer(&self) -> &Str {
        core::convert::From::<&[WideChar]>::from(unsafe { core::slice::from_raw_parts(
            self.buffer,
            self.capacity as usize / core::mem::size_of::<WideChar>()
        ) })
    }
}

impl<'a> core::convert::AsRef<Str> for StringW<'a> {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn as_ref(&self) -> &Str {
        core::convert::From::<&[WideChar]>::from(unsafe { core::slice::from_raw_parts(
            self.buffer,
            self.length as usize / core::mem::size_of::<WideChar>()
        ) })
    }
}

/// `length` will not contain the trailing zero-terminator, if `value` has one.
impl<'a> core::convert::From<&'a Str> for StringW<'a> {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn from(value: &'a Str) -> Self {
        Self {
            length: (
                (value.0.len() * core::mem::size_of::<WideChar>()) -
                (value.0.last().cloned() == Some(0)) as usize * core::mem::size_of::<WideChar>()
            ) as u16,
            capacity: (value.0.len() * core::mem::size_of::<WideChar>()) as u16,
            buffer: value.as_ptr(),
            _phantom: core::marker::PhantomData
        }
    }
}

/// Official documentation: [Working with Strings](https://docs.microsoft.com/en-us/windows/win32/learnwin32/working-with-strings).
pub type AnsiChar = u8;

/// Official documentation: [Working with Strings](https://docs.microsoft.com/en-us/windows/win32/learnwin32/working-with-strings).
///
/// Strings on Windows are encoded in UCS-2.
pub type WideChar = u16;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn str_conversion() {
        let d1 = [];
        let d2 = [];

        let s1: &AnsiStr = core::convert::From::from(d1.as_ref());
        let s2: &Str = core::convert::From::from(d2.as_ref());

        assert!(s1.is_empty());
        assert_eq!(s1.len(), 0);
        assert!(s2.is_empty());
        assert_eq!(s2.len(), 0);

        let d1 = [b'a', b'b', b'c'];
        let mut d2 = [b'a', b'b', b'c'];
        let d3 = ['a' as WideChar, 'b' as WideChar, 'c' as WideChar];
        let mut d4 = ['a' as WideChar, 'b' as WideChar, 'c' as WideChar];

        let s1: &AnsiStr = core::convert::From::from(d1.as_ref());
        let s2: &mut AnsiStr = core::convert::From::from(d2.as_mut());
        let s3: &Str = core::convert::From::from(d3.as_ref());
        let s4: &mut Str = core::convert::From::from(d4.as_mut());

        assert!(!s1.is_empty());
        assert_eq!(s1.len(), 3);
        assert!(!s2.is_empty());
        assert_eq!(s2.len(), 3);
        assert!(!s3.is_empty());
        assert_eq!(s3.len(), 3);
        assert!(!s4.is_empty());
        assert_eq!(s4.len(), 3);

        assert_eq!(s1, "abc");
        assert_eq!(s2, "abc");
        assert_eq!(s3, "abc");
        assert_eq!(s4, "abc");

        let r1: &[AnsiChar] = s1.into();
        let r2: &mut [AnsiChar] = s2.into();
        let r3: &[WideChar] = s3.into();
        let r4: &mut [WideChar] = s4.into();

        assert_eq!(r1, d1);
        assert_eq!(r2, d1);
        assert_eq!(r3, d3);
        assert_eq!(r4, d3);

        assert_eq!(&s1[1..], "bc");
        assert_eq!(&mut s2[1..], "bc");
        assert_eq!(&s3[1..], "bc");
        assert_eq!(&mut s4[1..], "bc");
    }

    #[test]
    fn str_from_terminated() {
        unsafe {
            assert_eq!(AnsiStr::from_terminated(
                [0].as_ptr(), None, false
            ), "\0");
            assert_eq!(Str::from_terminated(
                [0].as_ptr(), None, false
            ), "\0");

            assert_eq!(Str::from_terminated(
                [0].as_ptr(), None, true
            ), "");
            assert_eq!(AnsiStr::from_terminated(
                [0].as_ptr(), None, true
            ), "");

            assert_eq!(AnsiStr::from_terminated(
                [0].as_ptr(),
                Some(core::num::NonZeroUsize::new_unchecked(1)),
                false
            ), "\0");
            assert_eq!(Str::from_terminated(
                [0].as_ptr(),
                Some(core::num::NonZeroUsize::new_unchecked(1)),
                false
            ), "\0");

            assert_eq!(AnsiStr::from_terminated(
                [0].as_ptr(),
                Some(core::num::NonZeroUsize::new_unchecked(1)),
                true
            ), "");
            assert_eq!(Str::from_terminated(
                [0].as_ptr(),
                Some(core::num::NonZeroUsize::new_unchecked(1)),
                true
            ), "");

            assert_eq!(AnsiStr::from_terminated(
                [b'a', 0].as_ptr(), None, false
            ), "a\0");
            assert_eq!(Str::from_terminated(
                ['a' as WideChar, 0].as_ptr(), None, false
            ), "a\0");

            assert_eq!(AnsiStr::from_terminated(
                [b'a', 0].as_ptr(), None, true
            ), "a");
            assert_eq!(Str::from_terminated(
                ['a' as WideChar, 0].as_ptr(), None, true
            ), "a");

            assert_eq!(AnsiStr::from_terminated(
                [b'a', 0].as_ptr(),
                Some(core::num::NonZeroUsize::new_unchecked(1)),
                false
            ), "a");
            assert_eq!(Str::from_terminated(
                ['a' as WideChar, 0].as_ptr(),
                Some(core::num::NonZeroUsize::new_unchecked(1)),
                false
            ), "a");

            assert_eq!(AnsiStr::from_terminated(
                [b'a', 0].as_ptr(),
                Some(core::num::NonZeroUsize::new_unchecked(1)),
                true
            ), "a");
            assert_eq!(Str::from_terminated(
                ['a' as WideChar, 0].as_ptr(),
                Some(core::num::NonZeroUsize::new_unchecked(1)),
                true
            ), "a");

            assert_eq!(AnsiStr::from_terminated(
                [b'a', b'a', 0].as_ptr(), None, false
            ), "aa\0");
            assert_eq!(Str::from_terminated(
                ['a' as WideChar, 'a' as WideChar, 0].as_ptr(), None, false
            ), "aa\0");

            assert_eq!(AnsiStr::from_terminated(
                [b'a', b'a', 0].as_ptr(), None, true
            ), "aa");
            assert_eq!(Str::from_terminated(
                ['a' as WideChar, 'a' as WideChar, 0].as_ptr(), None, true
            ), "aa");

            assert_eq!(AnsiStr::from_terminated(
                [b'a', b'a', 0].as_ptr(),
                Some(core::num::NonZeroUsize::new_unchecked(1)),
                false
            ), "a");
            assert_eq!(Str::from_terminated(
                ['a' as WideChar, 'a' as WideChar, 0].as_ptr(),
                Some(core::num::NonZeroUsize::new_unchecked(1)),
                false
            ), "a");

            assert_eq!(AnsiStr::from_terminated(
                [b'a', b'a', 0].as_ptr(),
                Some(core::num::NonZeroUsize::new_unchecked(1)),
                true
            ), "a");
            assert_eq!(Str::from_terminated(
                ['a' as WideChar, 'a' as WideChar, 0].as_ptr(),
                Some(core::num::NonZeroUsize::new_unchecked(1)),
                true
            ), "a");
        }
    }

    #[test]
    fn str_into_lossy() {
        // ASCII only.
        let s1: &AnsiStr = core::convert::From::from("abc".as_bytes());
        let d2 = ['a' as WideChar, 'b' as WideChar, 'c' as WideChar];
        let s2: &Str = core::convert::From::from(d2.as_ref());

        assert_eq!(s1.into_lossy(), alloc::borrow::Cow::Borrowed("abc"));
        assert_eq!(s2.into_lossy(), alloc::borrow::Cow::Borrowed("abc"));

        // Non-ASCII included.
        let d1 = [b'a', 0x80, b'c'];
        let s1: &AnsiStr = core::convert::From::from(d1.as_ref());
        // UCS-2 character which is only 1 of the 2 necessary parts for a valid UTF-16 surrogate pair.
        let d2 = ['a' as WideChar, 0xD800, 'c' as WideChar];
        let s2: &Str = core::convert::From::from(d2.as_ref());

        assert_eq!(
            s1.into_lossy(),
            alloc::borrow::Cow::<str>::Owned(alloc::format!("a{}c", char::REPLACEMENT_CHARACTER))
        );
        assert_eq!(
            s2.into_lossy(),
            alloc::borrow::Cow::<str>::Owned(alloc::format!("a{}c", char::REPLACEMENT_CHARACTER))
        );
    }

    #[test]
    fn impl_string() {
        let s1 = String::from("Test 123\0");
        let s2 = s1.as_ref();
        let s3 = core::convert::Into::<&AnsiStr>::into("Test 123\0".as_bytes());

        let a_123 = core::convert::Into::<&AnsiStr>::into("123".as_bytes());
        let a_123_null = core::convert::Into::<&AnsiStr>::into("123\0".as_bytes());
        let a_best = core::convert::Into::<&AnsiStr>::into("Best".as_bytes());
        let a_test = core::convert::Into::<&AnsiStr>::into("Test".as_bytes());
        let w_123 = String::from("123");
        let w_123_null = String::from("123\0");
        let w_best = String::from("Best");
        let w_test = String::from("Test");

        assert!(s1.ends_with("123\0"));
        assert!(s1.ends_with(w_123_null.as_ref()));
        assert!(!s1.ends_with("123"));
        assert!(!s1.ends_with(w_123.as_ref()));
        assert!(s2.ends_with("123\0"));
        assert!(s2.ends_with(w_123_null.as_ref()));
        assert!(!s2.ends_with("123"));
        assert!(!s2.ends_with(w_123.as_ref()));
        assert!(s3.ends_with("123\0"));
        assert!(s3.ends_with(a_123_null));
        assert!(!s3.ends_with("123"));
        assert!(!s3.ends_with(a_123));

        assert!(s1.starts_with("Test"));
        assert!(s1.starts_with(w_test.as_ref()));
        assert!(!s1.starts_with("Best"));
        assert!(!s1.starts_with(w_best.as_ref()));
        assert!(s2.starts_with("Test"));
        assert!(s2.starts_with(w_test.as_ref()));
        assert!(!s2.starts_with("Best"));
        assert!(!s2.starts_with(w_best.as_ref()));
        assert!(s3.starts_with("Test"));
        assert!(s3.starts_with(a_test));
        assert!(!s3.starts_with("Best"));
        assert!(!s3.starts_with(a_best));
    }

    #[test]
    fn manipulate_utf8() {
        let mut s = String::from("ad");
        assert_eq!(s, "ad");

        s.insert_utf8(1, "bc");
        assert_eq!(s, "abcd");

        s.push_utf8("ef");
        assert_eq!(s, "abcdef");
    }

    #[test]
    fn print() {
        let string = String::from("A");
        let str = string.as_ref();

        assert_eq!("A", alloc::format!("{}", string));
        assert_eq!("A", alloc::format!("{}", str));
        assert_eq!("\"A\"", alloc::format!("{:?}", string));
        assert_eq!("\"A\"", alloc::format!("{:?}", str));
    }

    #[test]
    fn string_struct() {
        const TEST_DATA_A: &[(&[AnsiChar], u16, u16, &str, &str)] = &[
            (&[b'A'], 1, 1, "A", "A"),
            (&[b'A', 0], 2, 1, "A", "A\0"),
        ];

        for (input, capacity, length, data, buffer) in TEST_DATA_A {
            let str = StringA::from(Into::<&AnsiStr>::into(*input));
            assert_eq!(str.capacity, capacity * core::mem::size_of::<AnsiChar>() as u16);
            assert_eq!(str.length, length * core::mem::size_of::<AnsiChar>() as u16);
            assert_eq!(str.as_ref(), data);
            assert_eq!(str.buffer(), buffer);
        }

        const TEST_DATA_W: &[(&[WideChar], u16, u16, &str, &str)] = &[
            (&['A' as WideChar], 1, 1, "A", "A"),
            (&['A' as WideChar, 0], 2, 1, "A", "A\0"),
        ];

        for (input, capacity, length, data, buffer) in TEST_DATA_W {
            let str = StringW::from(Into::<&Str>::into(*input));
            assert_eq!(str.capacity, capacity * core::mem::size_of::<WideChar>() as u16);
            assert_eq!(str.length, length * core::mem::size_of::<WideChar>() as u16);
            assert_eq!(str.as_ref(), data);
            assert_eq!(str.buffer(), buffer);
        }
    }
}