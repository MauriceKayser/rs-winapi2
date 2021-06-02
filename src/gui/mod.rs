//! All gui related Windows types.

/// Official documentation: [Character Attributes](https://docs.microsoft.com/en-us/windows/console/char-info-str).
#[bitfield::bitfield(32)]
#[derive(Copy, Clone, Debug, Display, Eq, PartialEq)]
pub struct FillAttributes(pub FillAttribute);

/// Official documentation: [Character Attributes](https://docs.microsoft.com/en-us/windows/console/char-info-str).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug, bitfield::Flags)]
#[repr(u8)]
pub enum FillAttribute {
    ForegroundBlue,
    ForegroundGreen,
    ForegroundRed,
    ForegroundIntensity,
    BackgroundBlue,
    BackgroundGreen,
    BackgroundRed,
    BackgroundIntensity,
    CommonLvbLeadingByte,
    CommonLvbTrailingByte,
    CommonLvbGridHorizontal,
    CommonLvbGridLVertical,
    CommonLvbGridRVertical,
    CommonLvbReverseVideo = 14,
    CommonLvbUnderscore
}

/// Official documentation: [SW_* enum](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showwindow).
#[allow(missing_docs)]
#[derive(Copy, Clone, Debug)]
#[repr(u32)]
pub enum WindowVisibility {
    Hide,
    Normal,
    Minimized,
    Maximized,
    NormalNoActivate,
    Current,
    Minimize,
    MinimizedNoActivate,
    CurrentNoActivate,
    Restore,
    Default,
    ForceMinimize
}