//! Definitions for the SFrame format version 2.
//!
//! The SFrame specification is available at
//! <https://sourceware.org/binutils/docs-2.41/sframe-spec.html>.

use c_enum::c_enum;
use zerocopy::{AsBytes, ByteOrder, FromBytes, FromZeroes, Unaligned, I32, U16, U32};

use super::Preamble;

/// The header is the first part of an SFrame section.
///
/// It contains things that apply to the section as a whole and offsets to the
/// various other sub-sections defined in the format.
#[repr(packed)]
#[derive(Copy, Clone, Debug, AsBytes, FromBytes, FromZeroes, Unaligned)]
pub struct Header<O: ByteOrder> {
    /// The preamble for the format.
    pub preamble: Preamble<O>,

    /// The ABI/arch identifier.
    pub abi_arch: Abi,

    /// The CFA fixed FP offset, if any.
    pub fixed_fp_offset: i8,

    /// The CFA fixed RA offset, if any.
    pub fixed_ra_offset: i8,

    /// The size of the auxiliary header that follows the [`Header`], in bytes.
    pub auxhdr_len: u8,

    /// The number of SFrame FDEs in the section.
    pub num_fdes: U32<O>,

    /// The number of SFrame FREs in the section.
    pub num_fres: U32<O>,

    /// The length in bytes of the SFrame FRE sub-section.
    pub fre_len: U32<O>,

    /// The offset in bytes of the SFrame FDE sub-section.
    ///
    /// This sub-section contains `num_fdes` number of fixed-length array
    /// elements.
    pub fdeoff: U32<O>,

    /// The offset in bytes of the SFrame FRE sub-section, which describes the
    /// stack-trace information using variable-length array elements.
    pub freoff: U32<O>,
}

c_enum! {
    /// The ABI/arch of the target system for which the stack trace information
    /// contained in the SFrame section is intended.
    #[repr(transparent)]
    #[derive(Copy, Clone, Default, Eq, PartialEq, AsBytes, FromBytes, FromZeroes, Unaligned)]
    pub enum Abi: u8 {
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
#[repr(packed)]
#[derive(Copy, Clone, Debug, Default, AsBytes, FromBytes, FromZeroes, Unaligned)]
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

    // The size of the repetitive code block for which the
    pub rep_size: u8,

    // Extra padding for future fields.
    #[doc(hidden)]
    pub _padding2: U16<O>,
}

#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, AsBytes, FromBytes, FromZeroes, Unaligned)]
pub struct FdeInfo(pub u8);

impl FdeInfo {
    pub fn fretype(&self) -> FreType {
        match self.0 & 0x7 {
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

    pub fn set_fretype(&mut self, fretype: FreType) {
        self.0 &= !0x7;
        self.0 |= fretype as u8;
    }

    pub fn fdetype(&self) -> FdeType {
        match (self.0 >> 3) & 1 {
            0 => FdeType::PcInc,
            1 => FdeType::PcMask,
            _ => unreachable!(),
        }
    }

    pub fn set_fdetype(&mut self, fdetype: FdeType) {
        self.0 &= !(1 << 3);
        self.0 |= (fdetype as u8) << 3;
    }

    /// Specifies which key is used for signing the return addresses in the FDE.
    pub fn pauth_key(&self) -> Aarch64PauthKey {
        match (self.0 >> 4) & 1 {
            0 => Aarch64PauthKey::A,
            1 => Aarch64PauthKey::B,
            _ => unreachable!(),
        }
    }

    pub fn set_pauth_key(&mut self, pauth_key: Aarch64PauthKey) {
        self.0 &= !(1 << 4);
        self.0 |= (pauth_key as u8) << 4;
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
    ///
    /// > ## Note
    /// > In the V1 SFrame specification this meant that that the start address
    /// > should be used as a mask. So unwinders would perform
    /// > ```text
    /// > PC & FRE_START_ADDR_AS_MASK >= FRE_START_ADDR_AS_MASK
    /// > ```
    /// > to look up a matching FRE.
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

#[repr(packed)]
#[derive(Copy, Clone, Debug, Default, AsBytes, FromBytes, FromZeroes, Unaligned)]
pub struct FrameRowEntry<T> {
    pub start_address: T,
    pub info: FreInfo,
}

#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, AsBytes, FromBytes, FromZeroes, Unaligned)]
pub struct FreInfo(pub u8);

impl FreInfo {
    /// Distinguish between SP or FP based CFA recovery.
    pub fn cfa_base_reg_id(&self) -> FreBaseRegId {
        match self.0 & 1 {
            0 => FreBaseRegId::Sp,
            1 => FreBaseRegId::Fp,
            _ => unreachable!(),
        }
    }

    pub fn set_cfa_base_reg_id(&mut self, value: FreBaseRegId) {
        self.0 &= 0xFE;
        self.0 |= value as u8;
    }

    /// A value of up to 3 is allowed to track all three of CFA, FP, and RA.
    pub fn offset_count(&self) -> u8 {
        (self.0 >> 1) & 0x7
    }

    pub fn set_offset_count(&mut self, count: u8) {
        self.0 &= 0xE1;
        self.0 |= (count << 1) & 0x1E;
    }

    /// The size of the following stack offsets in bytes.
    pub fn offset_size(&self) -> FreOffset {
        match (self.0 >> 4) & 0x3 {
            0 => FreOffset::_1B,
            1 => FreOffset::_2B,
            2 => FreOffset::_4B,
            3 => FreOffset::_Reserved3,
            _ => unreachable!(),
        }
    }

    pub fn set_offset_size(&mut self, size: u8) {
        self.0 &= 0b10011111;
        self.0 |= (size << 4) & 0b01100000;
    }

    /// Indicates whether the return address is mangled with any authorization
    /// bits (signed RA).
    pub fn mangled_ra_p(&self) -> bool {
        (self.0 >> 7) & 1 != 0
    }

    pub fn set_mangled_ra_p(&mut self, value: bool) {
        self.0 &= 0b01111111;
        self.0 |= u8::from(value) << 7;
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

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum FreBaseRegId {
    Sp = 0,
    Fp = 1,
}
