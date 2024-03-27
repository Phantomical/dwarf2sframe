use alloc::collections::btree_map::Entry;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::iter::Peekable;
use core::num::NonZeroI8;
use core::{fmt, mem};

use tinyvec::ArrayVec;
use zerocopy::{AsBytes, ByteOrder, I16, I32, U16, U32};

use crate::raw::*;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SFrameOptions {
    flags: Flags,
    abi_arch: v2::Abi,
    fixed_fp_offset: Option<NonZeroI8>,
    fixed_ra_offset: Option<NonZeroI8>,
}

impl SFrameOptions {
    pub fn new() -> Self {
        Self {
            flags: Flags::FDE_SORTED,
            abi_arch: Default::default(),
            fixed_fp_offset: None,
            fixed_ra_offset: None,
        }
    }

    /// Whether functions preserve the frame pointer.
    pub fn frame_pointer(mut self, value: bool) -> Self {
        self.flags.set(Flags::FRAME_POINTER, value);
        self
    }

    /// Set the arch and endianness for the section.
    pub fn abi(mut self, abi: v2::Abi) -> Self {
        self.abi_arch = abi;
        self
    }

    /// Set the fixed offset of the frame pointer from the CFA.
    ///
    /// Note that setting this value to 0 is the same as setting it to `None`.
    pub fn fixed_fp_offset(mut self, offset: impl Into<Option<i8>>) -> Self {
        self.fixed_fp_offset = offset.into().and_then(NonZeroI8::new);
        self
    }

    /// Set the fixed offset of the return address from the CFA.
    ///
    /// Note that setting this value to 0 is the same as setting it to `None`.
    pub fn fixed_ra_offset(mut self, offset: impl Into<Option<i8>>) -> Self {
        self.fixed_ra_offset = offset.into().and_then(NonZeroI8::new);
        self
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum FreAddrSize {
    U8,
    U16,
    U32,
}

#[derive(Clone, Debug)]
pub struct SFrameBuilder {
    options: SFrameOptions,
    fdes: BTreeMap<i32, FuncDescBuilder>,
}

impl SFrameBuilder {
    pub fn new(options: SFrameOptions) -> Self {
        Self {
            options,
            fdes: BTreeMap::new(),
        }
    }

    pub fn options(&self) -> SFrameOptions {
        self.options
    }

    /// Add a new FDE to this SFrame section.
    ///
    /// If there is an existing frame with the same start address then it will
    /// be overridden.
    pub fn fde(&mut self, fde: FuncDescBuilder) {
        assert_eq!(self.options, fde.options);

        self.fdes.insert(fde.start_address, fde);
    }

    /// Attempt to merge adjacent FDEs into repeated [`v2::FdeType::PcMask`]
    /// FDEs.
    ///
    /// This feature was designed to work with repetitive blocks of code, such
    /// as program linkage tables but works fine as long as the blocks are
    /// adjacent and their FREs are equivalent.
    ///
    /// This method is meant make generating such optimized SFrame sections
    /// easier. The application can just worry about emitting unoptimized
    /// entries and merge them after the fact.
    pub fn merge_adjacent_fdes(&mut self) {
        let mut address = match self.fdes.first_key_value() {
            Some((key, _)) => *key,
            None => return,
        };

        loop {
            let mut iter = self.fdes.range_mut(address..);
            let current = match iter.next() {
                Some((_, current)) => current,
                None => break,
            };
            let next = match iter.next() {
                Some((_, next)) => next,
                None => break,
            };

            let saved = std::mem::replace(&mut address, next.start_address);

            debug_assert_eq!(current.options, next.options);
            if current.pauth_key != next.pauth_key {
                continue;
            }

            let relative = current.start_address - next.start_address;
            if relative as u32 != current.size {
                continue;
            }

            // This will emit an error when we attempt to build but we don't want to
            // acccidentally suppress that error with a bad merge.
            if current.size.checked_add(next.size).is_none() {
                continue;
            }

            match (current.rep_size, next.rep_size) {
                (Some(a), Some(b)) if a != b => continue,
                (Some(a), None) if a as u32 != next.size => continue,
                (None, Some(b)) if b as u32 != current.size => continue,
                (None, None) if current.size != next.size => continue,
                (None, None) if current.size > u8::MAX as u32 => continue,
                _ => (),
            }

            if current.fres != next.fres {
                continue;
            }

            current.rep_size = Some(match (current.rep_size, next.rep_size) {
                (Some(a), _) => a,
                (_, Some(b)) => b,
                _ => current.size as u8,
            });
            current.size += next.size;

            self.fdes.remove(&address);
            address = saved;
        }
    }

    pub fn build<O>(&self) -> Result<Vec<u8>, EmitError>
    where
        O: ByteOrder,
    {
        let mut fres: Vec<u8> = Vec::new();
        let mut output: Vec<u8> = Vec::with_capacity(
            mem::size_of::<v2::Header<O>>()
                + self.fdes.len() * mem::size_of::<v2::FuncDescEntry<O>>(),
        );
        output.resize(mem::size_of::<v2::Header<O>>(), 0);

        let has_overlapping_fde_ranges = self
            .fdes
            .values()
            .pairs(|a, b| {
                debug_assert!(a.start_address <= b.start_address);
                ((b.start_address - a.start_address) as u32) < a.size
            })
            .any(|v| v);
        if has_overlapping_fde_ranges {
            return Err(EmitError::OverlappingFdes);
        }

        let mut fre_count = 0;
        for fde in self.fdes.values() {
            let offset: u32 = match fres.len().try_into() {
                Ok(offset) => offset,
                Err(_) => return Err(EmitError::SectionTooLarge),
            };

            let max_offset = match fde.fres.last_key_value() {
                Some((_, fre)) => fre.start_address,
                None => 0,
            };

            let addr_ty = match max_offset {
                0..=0x7F => FreAddrSize::U8,
                0..=0x7FFF => FreAddrSize::U16,
                0..=0x7FFFFFFF => FreAddrSize::U32,

                // This should have been checked by the builder long before it could be added here.
                _ => unreachable!("FRE offsets with value >= 0x1000000 are not permitted"),
            };

            fre_count += fde.fres.len();
            let header = v2::FuncDescEntry::<O> {
                start_address: fde.start_address.into(),
                size: fde.size.into(),
                start_fre_off: offset.into(),
                num_fres: U32::new(
                    fde.fres
                        .len()
                        .try_into()
                        .map_err(|_| EmitError::SectionTooLarge)?,
                ),
                rep_size: fde.rep_size.unwrap_or(0),
                info: {
                    let mut info = v2::FdeInfo::default();
                    info.set_fdetype(fde.fdetype());
                    info.set_fretype(match addr_ty {
                        FreAddrSize::U8 => v1::FreType::Addr1,
                        FreAddrSize::U16 => v1::FreType::Addr2,
                        FreAddrSize::U32 => v1::FreType::Addr4,
                    });
                    info.set_pauth_key(fde.pauth_key);
                    info
                },
                ..Default::default()
            };

            output.extend_from_slice(header.as_bytes());

            for fre in fde.fres.values() {
                let offset_ty = fre
                    .offsets
                    .map(|o| o.offset_type())
                    .unwrap_or(FreAddrSize::U8);

                let mut values = ArrayVec::<[i32; 3]>::new();
                if let Some(offsets) = fre.offsets {
                    values.push(offsets.cfa);

                    if let Some(ra) = offsets.ra {
                        values.push(ra);
                    }

                    if let Some(fp) = offsets.fp {
                        values.push(fp);
                    }
                }
                let offsets = &values[..];

                let mut info = v2::FreInfo::default();
                info.set_offset_size(match offset_ty {
                    FreAddrSize::U8 => v2::FreOffset::_1B,
                    FreAddrSize::U16 => v2::FreOffset::_2B,
                    FreAddrSize::U32 => v2::FreOffset::_4B,
                });
                info.set_offset_count(offsets.len() as _);
                info.set_cfa_base_reg_id(fre.cfa_base_reg_id);
                info.set_mangled_ra_p(fre.mangled_ra_p);

                match addr_ty {
                    FreAddrSize::U8 => {
                        let header = v2::FrameRowEntry {
                            start_address: fre.start_address as u8,
                            info,
                        };

                        fres.extend_from_slice(header.as_bytes());
                    }
                    FreAddrSize::U16 => {
                        let header = v2::FrameRowEntry {
                            start_address: U16::<O>::new(fre.start_address as u16),
                            info,
                        };

                        fres.extend_from_slice(header.as_bytes());
                    }
                    FreAddrSize::U32 => {
                        let header = v2::FrameRowEntry {
                            start_address: U32::<O>::new(fre.start_address),
                            info,
                        };

                        fres.extend_from_slice(header.as_bytes());
                    }
                }

                match offset_ty {
                    FreAddrSize::U8 => {
                        for &offset in offsets {
                            fres.push(offset as i8 as u8);
                        }
                    }
                    FreAddrSize::U16 => {
                        for &offset in offsets {
                            fres.extend_from_slice(I16::<O>::new(offset as i16).as_bytes());
                        }
                    }
                    FreAddrSize::U32 => {
                        for &offset in offsets {
                            fres.extend_from_slice(I32::<O>::new(offset).as_bytes());
                        }
                    }
                }
            }
        }

        let fre_count = u32::try_from(fre_count).map_err(|_| EmitError::SectionTooLarge)?;

        let header = v2::Header::<O> {
            preamble: Preamble {
                magic: U16::new(MAGIC),
                version: Version::V2,
                flags: self.options.flags,
            },
            abi_arch: self.options.abi_arch,
            fixed_fp_offset: self.options.fixed_fp_offset.map(|fp| fp.get()).unwrap_or(0),
            fixed_ra_offset: self.options.fixed_ra_offset.map(|fp| fp.get()).unwrap_or(0),
            auxhdr_len: 0,
            num_fdes: U32::new(
                u32::try_from(self.fdes.len()).map_err(|_| EmitError::SectionTooLarge)?,
            ),
            num_fres: U32::new(u32::try_from(fre_count).map_err(|_| EmitError::SectionTooLarge)?),
            fre_len: U32::new(u32::try_from(fres.len()).map_err(|_| EmitError::SectionTooLarge)?),
            fdeoff: 0.into(),
            freoff: U32::new(
                u32::try_from(output.len() - mem::size_of::<v2::Header<O>>())
                    .map_err(|_| EmitError::SectionTooLarge)?,
            ),
        };

        output[..mem::size_of::<v2::Header<O>>()].copy_from_slice(header.as_bytes());
        output.extend_from_slice(&fres);
        Ok(output)
    }
}

#[derive(Clone, Debug)]
pub struct FuncDescBuilder {
    options: SFrameOptions,
    start_address: i32,
    size: u32,
    rep_size: Option<u8>,
    pauth_key: v2::Aarch64PauthKey,
    fres: BTreeMap<u32, FrameRowBuilder>,
}

impl FuncDescBuilder {
    pub fn new(options: SFrameOptions, start_address: i32, size: u32) -> Self {
        Self {
            options,
            start_address,
            rep_size: None,
            size,
            pauth_key: v2::Aarch64PauthKey::A,
            fres: BTreeMap::new(),
        }
    }

    pub fn pcinc(&mut self) -> &mut Self {
        self.rep_size = None;
        self
    }

    pub fn pcmask(&mut self, rep_size: u8) -> &mut Self {
        self.rep_size = Some(rep_size);
        self
    }

    pub fn start_address(&mut self, start_address: i32) -> &mut Self {
        self.start_address = start_address;
        self
    }

    pub fn size(&mut self, size: u32) -> &mut Self {
        self.size = size;
        self
    }

    pub fn pauth_key(&mut self, pauth_key: v2::Aarch64PauthKey) -> &mut Self {
        self.pauth_key = pauth_key;
        self
    }

    fn fdetype(&self) -> v2::FdeType {
        match self.rep_size {
            Some(_) => v2::FdeType::PcMask,
            None => v2::FdeType::PcInc,
        }
    }

    /// Attempt to merge adjacent identical FREs together.
    ///
    /// Sometimes there might be multiple sequential FREs that are identical.
    /// These can be merged together for some free space savings. This is not
    /// done automatically but this method can be used to do so if desired.
    ///
    /// Duplicate FREs are fairly easy to run into when building SFrame records
    /// based on a source that has more detailed unwind info. Instead of
    /// complicating the emission algorithm with it you can instead use this
    /// method to simplify it after-the-fact.
    pub fn merge_adjacent_fres(&mut self) {
        let mut address = match self.fres.first_key_value() {
            Some((key, _)) => *key,
            None => return,
        };

        loop {
            let mut iter = self.fres.range(address..);
            let current = match iter.next() {
                Some((_, current)) => current,
                None => break,
            };
            let next = match iter.next() {
                Some((_, next)) => next,
                None => break,
            };

            let saved = std::mem::replace(&mut address, next.start_address);

            let curr_za = FrameRowBuilder {
                start_address: 0,
                ..*current
            };
            let next_za = FrameRowBuilder {
                start_address: 0,
                ..*next
            };

            if curr_za != next_za {
                continue;
            }

            // We don't actually have to modify either of the FREs in order to merge them.
            // The way that FRE discovery goes means that removing the second one is
            // equivalent to merging.
            self.fres.remove(&address);
            address = saved;
        }
    }

    pub fn row(&mut self, mut row: FrameRowBuilder) -> Result<&mut Self, FrameRowError> {
        if row.start_address >= 0x10000000 {
            return Err(FrameRowError::StartAddressTooLarge);
        }

        if let Some(rep_size) = self.rep_size {
            if row.start_address >= rep_size as u32 {
                return Err(FrameRowError::StartAddressLargerThanRepSize);
            }
        }

        if row.start_address >= self.size {
            return Err(FrameRowError::StartAddressOutsideFde);
        }

        if let Some(offsets) = &mut row.offsets {
            if let Some(fixed_ra_offset) = self.options.fixed_ra_offset {
                let fixed_ra_offset: i32 = fixed_ra_offset.get().into();

                match offsets.ra {
                    Some(offset) if offset == fixed_ra_offset => offsets.ra = None,
                    Some(_) => return Err(FrameRowError::UnexpectedRaOffset),
                    None => (),
                }
            }

            if let Some(fixed_fp_offset) = self.options.fixed_fp_offset {
                let fixed_fp_offset: i32 = fixed_fp_offset.get().into();

                match offsets.fp {
                    Some(offset) if offset == fixed_fp_offset => offsets.fp = None,
                    Some(_) => return Err(FrameRowError::UnexpectedFpOffset),
                    None => (),
                }
            }
        }

        match self.fres.entry(row.start_address) {
            Entry::Occupied(_) => return Err(FrameRowError::DuplicateRow),
            Entry::Vacant(entry) => entry.insert(row),
        };

        Ok(self)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FrameRowBuilder {
    start_address: u32,
    offsets: Option<FrameRowOffsets>,
    mangled_ra_p: bool,
    cfa_base_reg_id: v2::FreBaseRegId,
}

impl FrameRowBuilder {
    pub fn new(base_reg: v2::FreBaseRegId, start_address: u32, offsets: FrameRowOffsets) -> Self {
        Self {
            cfa_base_reg_id: base_reg,
            start_address,
            offsets: Some(offsets),
            mangled_ra_p: false,
        }
    }

    pub fn invalid(start_address: u32) -> Self {
        Self {
            cfa_base_reg_id: v2::FreBaseRegId::Fp,
            start_address,
            offsets: None,
            mangled_ra_p: false,
        }
    }

    pub fn new_from_sp(start_address: u32, offsets: FrameRowOffsets) -> Self {
        Self::new(v2::FreBaseRegId::Sp, start_address, offsets)
    }

    pub fn new_from_fp(start_address: u32, offsets: FrameRowOffsets) -> Self {
        Self::new(v2::FreBaseRegId::Fp, start_address, offsets)
    }

    pub fn mangled_ra_p(mut self, value: bool) -> Self {
        self.mangled_ra_p = value;
        self
    }
}

/// The offsets used to actually do the unwinding.
///
/// This specifies how, starting with a base register, the unwinder can
/// determine first the canonical frame address (CFA) and then use that to
/// determine the return address (RA) and frame pointer (FP) of the subsequent
/// frame.
///
/// The FP and RA offsets may optionally be specified as part of the section
/// header. In that case those offsets _must_ be absent in the serialized FRE.
/// As a convenience, this library allows them to be set as long as they are
/// equal to the values contained in the header.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FrameRowOffsets {
    /// The offset used to locate the canonical frame address (CFA).
    ///
    /// When unwinding happens, it will be used to compute the offset of the CFA
    /// from the configured base register (by doing `BASE_REG + offset`).
    pub cfa: i32,

    /// The offset used to calculate the return address.
    ///
    /// When unwinding happens, it will be used to compute the offset of the RA
    /// from the CFA (by doing `CFA + offset`).
    ///
    /// This _must_ be present if [`SFrameOptions::fixed_ra_offset`] is `None`
    /// and must otherwise be `None` or equal to the provided `fixed_ra_offset`.
    pub ra: Option<i32>,

    /// The offset used to calculate the frame pointer.
    ///
    /// When unwinding happens, it will be used to compute the offset of the FP
    /// from the CFA (by doing `CFA + offset`).
    ///
    /// This _must_ be present if [`SFrameOptions::fixed_fp_offset`] is `None`
    /// and must otherwise be `None` or equal to the provided `fixed_fp_offset`.
    pub fp: Option<i32>,
}

impl FrameRowOffsets {
    fn offset_type(&self) -> FreAddrSize {
        let mut max = self.cfa;

        if let Some(ra) = self.ra {
            if max.unsigned_abs() < ra.unsigned_abs() {
                max = ra;
            }
        }

        if let Some(fp) = self.fp {
            if max.unsigned_abs() < fp.unsigned_abs() {
                max = fp;
            }
        }

        match max {
            -0x80..=0x7F => FreAddrSize::U8,
            -0x8000..=0x7FFF => FreAddrSize::U16,
            _ => FreAddrSize::U32,
        }
    }
}

/// An error emitted when building a [`FrameRowBuilder`].
#[non_exhaustive]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FrameRowError {
    /// The `start_address` of a [`FrameRowBuilder`] was larger than the format
    /// allows.
    ///
    /// The SFrame format only allows addresses of up to 0x10000000 to be stored
    /// in the format. If you have a function that is larger than 2GiB you are
    /// likely out of luck.
    ///
    /// Note that SFrame provides no way to represent function addresses larger
    /// than 2GB (`i32::MAX`) since the function address is an `i32`.
    StartAddressTooLarge,

    /// On a FDE whose type is `PCMASK` the `start_address` of a
    /// [`FrameRowBuilder`] was larger than the `rep_size`.
    ///
    /// This means that it would be impossible for an unwinder to ever use such
    /// a frame. As such, this is considered to be an error.
    StartAddressLargerThanRepSize,

    /// The start address of a FRE falls outside the address range of the FDE it
    /// belongs to.
    StartAddressOutsideFde,

    /// The RA offset was expected to be present but `None` was provided
    /// instead.
    MissingRaOffset,

    /// The FP offset was expected to be present but `None` was provided
    /// instead.
    MissingFpOffset,

    /// The RA offset was already provided as a section option in
    /// [`SFrameOptions`] and the RA offset specified in [`FrameRowOffsets`] was
    /// different.
    ///
    /// The SFrame format doesn't allow FREs to specify a RA offset that is
    /// already specified in the section header. This library allows this as a
    /// convenience provided that it is equal to the one already contained
    /// within the section header.
    UnexpectedRaOffset,

    /// The RA offset was already provided as a section option in
    /// [`SFrameOptions`] and the RA offset specified in [`FrameRowOffsets`] was
    /// different.
    ///
    /// The SFrame format doesn't allow FREs to specify a FP offset that is
    /// already specified in the section header. This library allows this as a
    /// convenience provided that it is equal to the one already contained
    /// within the section header.
    UnexpectedFpOffset,

    /// The [`FuncDescBuilder`] already has a [`FrameRowBuilder`] registered at
    /// this offset.
    DuplicateRow,
}

impl fmt::Display for FrameRowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::StartAddressTooLarge => "FRE start offset was larger than 0x10000000",
            Self::StartAddressLargerThanRepSize => {
                "FRE start offset was larger than the specified FDE repetition size"
            }
            Self::StartAddressOutsideFde => {
                "FRE start address outside of the address range of its FDE"
            }
            Self::MissingRaOffset => "FRE was missing a required offset for the return address",
            Self::MissingFpOffset => "FRE was missing a required offset for the frame pointer",
            Self::UnexpectedRaOffset => {
                "provided return address offset did not match the offset specified in the section \
                 header"
            }
            Self::UnexpectedFpOffset => {
                "provided function pointer offset did not match the one specified in the section \
                 header"
            }
            Self::DuplicateRow => "FDE already contains a row with the same start address",
        };

        f.write_str(msg)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FrameRowError {}

#[non_exhaustive]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum EmitError {
    /// The builder contains multiple FDEs that have overlapping ranges.
    ///
    /// Emitted FDEs are searched via binary search so this would mean that
    /// unwinding would be unpredictable for those addresses which are covered
    /// by multiple FDEs.
    OverlappingFdes,

    /// The FRE sub-section would be larger than u32::MAX.
    ///
    /// The SFrame format does not have any way to represent such a section so
    /// attempting to create one is an error.
    SectionTooLarge,
}

impl fmt::Display for EmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::OverlappingFdes => "multiple FDEs cover the same address ranges",
            Self::SectionTooLarge => {
                "sframe section length would be too large to represent offsets"
            }
        };

        f.write_str(msg)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EmitError {}

trait PairsExt: Iterator {
    fn pairs<F, R>(self, func: F) -> Pairs<Self, F>
    where
        F: FnMut(Self::Item, &Self::Item) -> R,
        Self: Sized,
    {
        Pairs::new(self, func)
    }
}

impl<I: Iterator> PairsExt for I {}

struct Pairs<I: Iterator, F> {
    iter: Peekable<I>,
    func: F,
}

impl<I: Iterator, F> Pairs<I, F> {
    pub fn new(iter: I, func: F) -> Self {
        Self {
            iter: iter.peekable(),
            func,
        }
    }
}

impl<I, F, R> Iterator for Pairs<I, F>
where
    I: Iterator,
    F: FnMut(I::Item, &I::Item) -> R,
{
    type Item = R;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.iter.next()?;
        let peek = self.iter.peek()?;

        Some((self.func)(item, peek))
    }
}
