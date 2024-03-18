use crate::raw::v2;

pub enum ReadError {
    /// Found an unsupported SFrame version.
    UnsupportedVersion(u8),

    /// Found an unsupported FDE type.
    UnsupportedFdeType(v2::FdeType),

    /// Found an unsupported FDE type.
    UnsupportedFreType(v2::FreType),

    /// Found an unsupported FRE offset type.
    UnsupportedFreOffset(v2::FreOffset),

    /// Hit the end of input before it was expected.
    UnexpectedEof,

    /// The configured endianness does not match that of the section.
    IncorrectEndian,

    /// The requested FDE index was out of range.
    InvalidFdeIndex,

    /// A FRE specified more than 3 offsets.
    InvalidFreOffsetCount(u8),

    /// The FDE repeated block size had a value of 0.
    InvalidFdeRepBlockSize,

    /// An expected offset was missing from a FRE.
    MissingFreOffset,
}
