//! Errors for DWARF to SFrame conversion.

use std::fmt;

#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum Error {
    /// An error occurred while iterating through the entries of the `.eh_frame`
    /// section.
    InvalidEhFrameEntry(gimli::Error),

    /// An error occurred while attempting to parse a DWARF FDE.
    InvalidDwarfFde(gimli::Error),

    /// An error occurred while attempting to parse the unwind table of a DWARF
    /// FDE.
    InvalidUnwindTable(gimli::Error),

    /// A DWARF FDE had a start address that was larger than `i32::MAX`.
    ///
    /// The SFrame format uses a signed 32-bit integer to represent addresses in
    /// the file so addresses larger than `i32::MAX` are not representable.
    InvalidStartAddress { address: u64 },

    /// A DWARF unwind table had a start address offset that was larger than
    /// `i32::MAX`.
    ///
    /// The SFrame format uses a signed 32-bit integer to represent addresses in
    /// the file so addresses larger than `i32::MAX` are not representable.
    InvalidRowOffset { address: u64, offset: u64 },

    /// A DWARF FDE had a length larger that was larger than `i32::MAX`.
    ///
    /// The SFrame format does not allow function offsets larger than `i32:MAX`
    /// so attempting to convert info for a function with such a length will
    /// error.
    InvalidFunctionLength { address: u64, len: u64 },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEhFrameEntry(e) => write!(f, "invalid .eh_frame entry: {e}"),
            Self::InvalidDwarfFde(e) => write!(f, "invalid DWARF FDE: {e}"),
            Self::InvalidUnwindTable(e) => write!(f, "invalid DWARF unwind table: {e}"),
            Self::InvalidStartAddress { address } => {
                write!(
                    f,
                    "DWARF FDE start address {address:#x} larger than 0x10000000"
                )
            }
            Self::InvalidRowOffset { offset, .. } => {
                write!(f, "DWARF FDE row offset {offset:#x} larger than 0x10000000")
            }
            Self::InvalidFunctionLength { address, len } => {
                write!(
                    f,
                    "DWARF FDE for address {address:#x} had length {len:#x} larger than 0x10000000"
                )
            }
        }
    }
}

impl std::error::Error for Error {}
