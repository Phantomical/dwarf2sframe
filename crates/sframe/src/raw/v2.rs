//! Definitions for the SFrame format version 2.
//!
//! The SFrame specification is available at
//! <https://sourceware.org/binutils/docs-2.41/sframe-spec.html>.

use c_enum::c_enum;

use super::Preamble;

/// The header is the first part of an SFrame section.
///
/// It contains things that apply to the section as a whole and offsets to the
/// various other sub-sections defined in the format.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Header {
    /// The preamble for the format.
    pub preamble: Preamble,

    /// The ABI/arch identifier.
    pub abi_arch: u8,

    /// The CFA fixed FP offset, if any.
    pub fixed_fp_offset: i8,

    /// The CFA fixed RA offset, if any.
    pub fixed_ra_offset: i8,

    /// The size of the auxiliary header that follows the [`Header`], in bytes.
    pub auxhdr_len: u8,

    /// The number of SFrame FDEs in the section.
    pub num_fdes: u32,

    /// The number of SFrame FREs in the section.
    pub num_fres: u32,

    /// The length in bytes of the SFrame FRE sub-section.
    pub fre_len: u32,

    /// The offset in bytes of the SFrame FDE sub-section.
    ///
    /// This sub-section contains `num_fdes` number of fixed-length array
    /// elements.
    pub fdeoff: u32,

    /// The offset in bytes of the SFrame FRE sub-section, which describes the
    /// stack-trace information using variable-length array elements.
    pub freoff: u32,
}

c_enum! {
    /// The ABI/arch of the target system for which the stack trace information
    /// contained in the SFrame section is intended.
    #[derive(Copy, Clone, Eq, PartialEq)]
    pub enum Abi: u32 {
        AARCH64_ENDIAN_BIG = 1,
        AARCH64_ENDIAN_LITTLE = 2,
        AMD64_ENDIAN_LITTLE = 3,
    }
}

/// A single function descriptor entry.
///
/// The SFrame FDE sub-section is a sorted list of this struct. Each FDE
/// contains information to describe a function's stack trace information at a
/// high level.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FuncDescEntry {
    /// The virtual memory address of the described function.
    pub func_start_address: i32,

    /// The size of the function in bytes.
    pub func_size: u32,

    /// The offset in bytes of the function's first SFrame FRE in the sframe
    /// section.
    ///
    /// Note that this offset is relative to _the end of the SFrame FDE
    /// sub-section_ (unlike offsets in the SFrame header, which are relative to
    /// the _end_ of the sframe header).
    pub func_start_fre_off: u32,

    /// The total number of FREs used for the function.
    pub func_num_fres: u32,

    /// The FDE info word.
    pub func_info: u8,

    // The size of the repetitive code block for which the
    pub func_rep_size: u8,

    // Extra padding for future fields.
    _padding2: u16,
}

impl FuncDescEntry {
    pub fn fretype(&self) -> FreType {
        match self.func_info & 0x7 {
            0 => FreType::Addr1,
            1 => FreType::Addr2,
            2 => FreType::Addr4,
            3 => FreType::_Reserved3,
            4 => FreType::_Reserved4,
            5 => FreType::_Reserved5,
            6 => FreType::_Reserved6,
            7 => FreType::_Reserved7,
            _ => unreachable!(),
        }
    }

    pub fn fdetype(&self) -> FdeType {
        match (self.func_info >> 3) & 1 {
            0 => FdeType::PcInc,
            1 => FdeType::PcMask,
            _ => unreachable!(),
        }
    }

    /// Specifies which key is used for signing the return addresses in the FDE.
    pub fn pauth_key(&self) -> Aarch64PauthKey {
        match (self.func_info >> 4) & 1 {
            0 => Aarch64PauthKey::A,
            1 => Aarch64PauthKey::B,
            _ => unreachable!(),
        }
    }
}

/// Specifies which key is used for signing the return addresses in the SFrame
/// FDE.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Aarch64PauthKey {
    A = 0,
    B = 1,
}

/// The type of which FDE type to use.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum FdeType {
    /// Unwinders perform (`PC >= FRE_START_ADDR`) to look up a matching FRE.
    PcInc = 0,

    /// Unwinders perform (`PC % REP_BLOCK_SIZE >= FRE_START_ADDR`) to look up a
    /// matching FRE.
    ///
    /// `REP_BLOCK_SIZE` is the size in bytes of the repeating block of program
    /// instructions.
    PcMask = 1,
}

/// The types of FRE entries used to represent the stack trace information.
#[repr(u8)]
#[non_exhaustive]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum FreType {
    /// The start address offset (in bytes) of the FRE is an unsigned 8-bit
    /// value.
    Addr1 = 0,

    /// The start address offset (in bytes) of the FRE is an unsigned 16-bit
    /// value.
    Addr2 = 1,

    /// The start address offset (in bytes) of the FRE is an unsigned 32-bit
    /// value.
    Addr4 = 2,

    // Reserved branches so that we can actually represent the full domain that can be encoded in
    // the spec.
    #[doc(hidden)]
    _Reserved3 = 3,
    #[doc(hidden)]
    _Reserved4 = 4,
    #[doc(hidden)]
    _Reserved5 = 5,
    #[doc(hidden)]
    _Reserved6 = 6,
    #[doc(hidden)]
    _Reserved7 = 7,
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FrameRowEntry<T> {
    pub start_address: T,
    pub info: u8,
}

impl<T> FrameRowEntry<T> {
    /// Distinguish between SP or FP based CFA recovery.
    pub fn cfa_base_reg_id(&self) -> bool {
        self.info & 1 != 0
    }

    /// A value of up to 3 is allowed to track all three of CFA, FP, and RA.
    pub fn offset_count(&self) -> u8 {
        (self.info >> 1) & 0x7
    }

    /// The size of the following stack offsets in bytes.
    pub fn offset_size(&self) -> FreOffset {
        match (self.info >> 4) & 0x3 {
            0 => FreOffset::_1B,
            1 => FreOffset::_2B,
            2 => FreOffset::_4B,
            3 => FreOffset::_Reserved3,
            _ => unreachable!(),
        }
    }

    /// Indicates whether the return address is mangled with any authorization
    /// bits (signed RA).
    pub fn mangled_ra_p(&self) -> bool {
        (self.info >> 7) & 1 != 0
    }
}

#[repr(u8)]
#[non_exhaustive]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum FreOffset {
    _1B = 0,
    _2B = 1,
    _4B = 2,

    #[doc(hidden)]
    _Reserved3 = 3,
}
