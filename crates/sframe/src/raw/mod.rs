//! Raw struct types representing structures in the SFrame spec.

use bitflags::bitflags;
use c_enum::c_enum;

pub mod v2;

/// The initial preamble structure.
///
/// This is the only part of the format that is not permitted to vary between
/// versions.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Preamble {
    /// A magic number for a SFrame section.
    ///
    /// This is defined to be 0xDEE2 (see [`MAGIC`]) but can be used to detect
    /// if the section was encoded with a different endian than the current
    /// platform.
    pub magic: u16,

    /// The version number of this SFrame section.
    pub version: Version,

    /// Section-wide flags for this section.
    pub flags: Flags,
}

/// The magic number for the SFrame section.
///
/// This is defined to be 0xDEE2 but if is read on a system who's endianness
/// does not match the target endian then it will be reversed.
pub const MAGIC: u16 = 0xDEE2;

c_enum! {
    /// The version of the SFrame format.
    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
    pub enum Version: u8 {
        /// First version, now obsolete.
        V1 = 1,

        /// Second version, under development.
        V2 = 2,
    }
}

bitflags! {
    /// Bitflags that describe various section-wide properties.
    #[repr(transparent)]
    #[derive(Copy, Clone, Debug, Default)]
    pub struct Flags: u8 {
        /// Fucntion descriptor entries are sorted on PC.
        const FDE_SORTED = 0x1;

        /// Functions preserve the frame pointer.
        const FRAME_POINTER = 0x2;
    }
}