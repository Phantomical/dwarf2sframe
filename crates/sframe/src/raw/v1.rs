//! Definitions for the SFrame format version 1.
//!
//! Note that SFrame V1 is deprecated and shouldn't be used for new development.
//! This format reuses most of the structures from the V2 format with the
//! exception of [`FuncDescEntry`].
//!
//! The SFrame specification is available at
//! <https://sourceware.org/binutils/docs-2.40/sframe-spec.html>.

use zerocopy::{ByteOrder, FromBytes, FromZeroes, I32, U32};

pub use super::v2::*;

/// A single function descriptor entry.
///
/// The SFrame FDE sub-section is a sorted list of this struct. Each FDE
/// contains information to describe a function's stack trace information at a
/// high level.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, FromBytes, FromZeroes)]
pub struct FuncDescEntry<O: ByteOrder> {
    /// The virtual memory address of the described function.
    pub start_address: I32<O>,

    /// The size of the function in bytes.
    pub size: U32<O>,

    /// The offset in bytes of the function's first SFrame FRE in the sframe
    /// section.
    ///
    /// Note that this offset is relative to _the end of the SFrame FDE
    /// sub-section_ (unlike offsets in the SFrame header, which are relative to
    /// the _end_ of the sframe header).
    pub start_fre_off: U32<O>,

    /// The total number of FREs used for the function.
    pub num_fres: U32<O>,

    /// The FDE info word.
    pub info: FdeInfo,
}
