//! All string related Windows types.

use alloc::vec::Vec;

/// Generic string comparison functions.
pub trait ImplString<T> {
    /// Returns `true` if this string slice ends with the given sub string.
    fn ends_with(&self, sub: T) -> bool;

    /// Returns `true` if this string slice starts with with the given sub string.
    fn starts_with(&self, sub: T) -> bool;
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
        self as *mut _ as *mut WideChar
    }

    /// Returns a raw pointer to the slice's buffer.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn as_ptr(&self) -> *const WideChar {
        self as *const _ as *const WideChar
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

    /// Returns a zero-terminated string reference from a zero-terminated string pointer.
    pub unsafe fn from_terminated<'a>(
        terminated_string: *const WideChar,
        exclude_zero_terminator: bool
    ) -> &'a Self {
        Self::from_terminated_mut(terminated_string as _, exclude_zero_terminator)
    }

    /// Returns a zero-terminated, mutable string reference from a zero-terminated string pointer.
    pub unsafe fn from_terminated_mut<'a>(
        terminated_string: *mut WideChar,
        exclude_zero_terminator: bool
    ) -> &'a mut Self {
        let mut count = 0;

        loop {
            if terminated_string.add(count).read() == 0 {
                return core::convert::From::<&mut [WideChar]>::from(core::slice::from_raw_parts_mut(
                    terminated_string,
                    count + (!exclude_zero_terminator) as usize
                ));
            }

            count += 1;
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

impl ImplString<&Str> for Str {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn ends_with(&self, sub: &Str) -> bool {
        if self.len() < sub.len() { return false; }

        self.0[self.len() - sub.len()..] == sub.0
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn starts_with(&self, sub: &Str) -> bool {
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

impl core::ops::IndexMut<usize> for Str {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl core::ops::Index<core::ops::RangeInclusive<usize>> for Str {
    type Output = Str;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index(&self, index: core::ops::RangeInclusive<usize>) -> &Str {
        core::convert::From::from(&self.0[index])
    }
}

impl core::ops::IndexMut<core::ops::RangeInclusive<usize>> for Str {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index_mut(&mut self, index: core::ops::RangeInclusive<usize>) -> &mut Self::Output {
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
    fn ends_with(&self, sub: &String) -> bool {
        self.as_ref().ends_with(sub.as_ref())
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn starts_with(&self, sub: &String) -> bool {
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

impl core::ops::IndexMut<usize> for String {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl core::ops::Index<core::ops::RangeInclusive<usize>> for String {
    type Output = Str;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index(&self, index: core::ops::RangeInclusive<usize>) -> &Str {
        core::convert::From::from(&self.0[index])
    }
}

impl core::ops::IndexMut<core::ops::RangeInclusive<usize>> for String {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index_mut(&mut self, index: core::ops::RangeInclusive<usize>) -> &mut Self::Output {
        core::convert::From::from(&mut self.0[index])
    }
}

impl core::ops::Index<core::ops::RangeFull> for String {
    type Output = Str;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index(&self, _index: core::ops::RangeFull) -> &Str {
        core::convert::From::<&[WideChar]>::from(self.0.as_slice())
    }
}

impl core::ops::IndexMut<core::ops::RangeFull> for String {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn index_mut(&mut self, _index: core::ops::RangeFull) -> &mut Str {
        core::convert::From::<&mut [WideChar]>::from(self.0.as_mut_slice())
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

impl<'a> core::convert::Into<&'a Str> for &'a StringW<'a> {
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn into(self) -> &'a Str {
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
///
/// Strings on Windows are encoded in WTF-16.
pub type WideChar = u16;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_terminated() {
        unsafe {
            assert_eq!(Str::from_terminated(
                [0].as_ptr(), false
            ), "\0");
            assert_eq!(Str::from_terminated(
                [0].as_ptr(), true
            ), "");
            assert_eq!(Str::from_terminated(
                [b'a' as WideChar, 0].as_ptr(), false
            ), "a\0");
            assert_eq!(Str::from_terminated(
                [b'a' as WideChar, 0].as_ptr(), true
            ), "a");
        }
    }

    #[test]
    fn impl_string() {
        let s = String::from("Test 123\0");

        assert!(s.ends_with("123\0"));
        assert!(!s.ends_with("123"));

        assert!(s.starts_with("Test"));
        assert!(!s.starts_with("Best"));

        assert!(s.as_ref().ends_with(String::from("123\0").as_ref()));
        assert!(!s.as_ref().ends_with(String::from("123").as_ref()));

        assert!(s.as_ref().starts_with(String::from("Test").as_ref()));
        assert!(!s.as_ref().starts_with(String::from("Best").as_ref()));
    }

    #[test]
    fn insert_utf8() {
        let mut s = String::from("ad");
        assert_eq!(s, "ad");

        s.insert_utf8(1, "bc");
        assert_eq!(s, "abcd");
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
    fn string_w() {
        const TEST_DATA: &[(&[WideChar], u16, u16, &str, &str)] = &[
            (&['A' as WideChar], 1, 1, "A", "A"),
            (&['A' as WideChar, 0], 2, 1, "A", "A\0"),
        ];

        for (input, capacity, length, data, buffer) in TEST_DATA {
            let str = StringW::from(Into::<&Str>::into(*input));
            assert_eq!(str.capacity, capacity * core::mem::size_of::<WideChar>() as u16);
            assert_eq!(str.length, length * core::mem::size_of::<WideChar>() as u16);
            assert_eq!(Into::<&Str>::into(&str), data);
            assert_eq!(str.buffer(), buffer);
        }
    }
}