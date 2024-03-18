use core::fmt;

use crate::raw::v2;

/// An error emitted while attempting to read an sframe section.
#[non_exhaustive]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
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

    /// A FRE specified more than 3 offsets.
    InvalidFreOffsetCount(u8),

    /// The FDE repeated block size had a value of 0.
    InvalidFdeRepBlockSize,

    /// An expected offset was missing from a FRE.
    MissingFreOffset,
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported sframe version ({version})")
            }
            Self::UnsupportedFdeType(ty) => write!(f, "unsupported FDE type ({})", *ty as u8),
            Self::UnsupportedFreType(ty) => write!(f, "unsupported FRE type ({})", *ty as u8),
            Self::UnsupportedFreOffset(ty) => {
                write!(f, "unsupported FRE offset type ({})", *ty as u8)
            }
            Self::UnexpectedEof => write!(f, "unexpected end-of-input when reading sframe section"),
            Self::IncorrectEndian => write!(
                f,
                "the section endianness does not match that of the reader"
            ),
            Self::InvalidFdeRepBlockSize => write!(f, "FDE had a repeated block size of 0"),
            Self::MissingFreOffset => write!(f, "FRE was missing an expected offset"),
            Self::InvalidFreOffsetCount(count) => write!(
                f,
                "FRE had too many offset values (expected 1 to 3, got {count} instead)"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ReadError {}
