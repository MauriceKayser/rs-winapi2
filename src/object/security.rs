//! All object security related Windows types.

// TODO: Implement struct `Descriptor`.
/// Official documentation: [SECURITY_DESCRIPTOR struct](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_security_descriptor).
#[repr(C)]
pub struct Descriptor(u8);

// TODO: Implement struct `QualityOfService`.
/// Official documentation: [SECURITY_QUALITY_OF_SERVICE struct](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_quality_of_service).
#[repr(C)]
pub struct QualityOfService(u8);