//! Errors for DWARF to SFrame conversion.

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
    InvalidRowOffset { address: u64 },

    /// A DWARF FDE had a length larger that was larger than `i32::MAX`.
    ///
    /// The SFrame format does not allow function offsets larger than `i32:MAX`
    /// so attempting to convert info for a function with such a length will
    /// error.
    InvalidFunctionLength { address: u64, len: u64 },

    /// A DWARF unwind table row had an offset larger than `i32::MAX`.
    ///
    /// The SFrame format does not support this so an error was emitted instead.
    InvalidFunctionOffset { address: u64, offset: u64 },
}
