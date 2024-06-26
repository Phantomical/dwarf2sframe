use core::cmp::Ordering;
use core::iter::FusedIterator;
use core::{array, fmt, mem};

use zerocopy::{ByteOrder, FromBytes, NativeEndian, I16, I32, U16, U32};

use crate::raw::*;
use crate::ReadError;

/// A SFrame ELF section.
pub struct SFrame<'a, O: ByteOrder = NativeEndian> {
    preamble: Preamble<O>,
    abi_arch: v2::Abi,
    fixed_fp_offset: i8,
    fixed_ra_offset: i8,

    num_fdes: u32,
    num_fres: u32,

    aux: &'a [u8],
    fdes: FdeList<'a, O>,
    fres: &'a [u8],
}

impl<'a, O: ByteOrder> SFrame<'a, O> {
    pub fn load(section: &'a [u8]) -> Result<Self, ReadError> {
        let preamble = match Preamble::<O>::ref_from_prefix(section) {
            Some(preamble) if preamble.magic.get() != MAGIC => {
                return Err(ReadError::IncorrectEndian)
            }
            Some(preamble) => preamble,
            None => return Err(ReadError::UnexpectedEof),
        };

        match preamble.version {
            Version::V1 | Version::V2 => (),
            _ => return Err(ReadError::UnsupportedVersion(preamble.version.0)),
        };

        let header = match v2::Header::<O>::ref_from_prefix(section) {
            Some(header) => header,
            None => return Err(ReadError::UnexpectedEof),
        };

        let data = &section[mem::size_of_val(header)..];
        let aux = data
            .get(..header.auxhdr_len as usize)
            .ok_or(ReadError::UnexpectedEof)?;

        // Aux header counts towards the header size so offsets are relative to the end
        // of the aux header.
        let data = &data[aux.len()..];

        let fdes = data
            .get(header.fdeoff.get() as usize..)
            .ok_or(ReadError::UnexpectedEof)?;

        let fdes = match preamble.version {
            Version::V1 => {
                let (fdes, _) =
                    v1::FuncDescEntry::<O>::slice_from_prefix(fdes, header.num_fdes.get() as usize)
                        .ok_or(ReadError::UnexpectedEof)?;

                FdeList::V1(fdes)
            }
            Version::V2 => {
                let (fdes, _) =
                    v2::FuncDescEntry::<O>::slice_from_prefix(fdes, header.num_fdes.get() as usize)
                        .ok_or(ReadError::UnexpectedEof)?;

                FdeList::V2(fdes)
            }

            version => unreachable!("missing support for SFrame version {}", version.0),
        };

        let fres = data
            .get(
                header.freoff.get() as usize
                    ..header.freoff.get() as usize + header.fre_len.get() as usize,
            )
            .ok_or(ReadError::UnexpectedEof)?;

        Ok(Self {
            preamble: header.preamble,
            abi_arch: header.abi_arch,
            fixed_fp_offset: header.fixed_fp_offset,
            fixed_ra_offset: header.fixed_ra_offset,
            num_fdes: header.num_fdes.get(),
            num_fres: header.num_fres.get(),
            aux,
            fdes,
            fres,
        })
    }

    /// The SFrame specification verison that this section uses.
    pub fn version(&self) -> Version {
        self.preamble.version
    }

    /// Section-wide SFrame flags.
    pub fn flags(&self) -> Flags {
        self.preamble.flags
    }

    /// Information about the arch (endianness) and ABI.
    pub fn abi(&self) -> v1::Abi {
        self.abi_arch
    }

    /// The bytes that make up the auxiliary header.
    ///
    /// This is not used by the SFrame format at the moment but in the future it
    /// may be used to extend the information specified in the SFrame header.
    pub fn raw_aux(&self) -> &[u8] {
        self.aux
    }

    /// Return the fixed Frame Pointer offset from the CFA, if any.
    ///
    /// The offset for the Frame Pointer (FP) from CFA is fixed for some ABIs.
    /// (e.g. in AMD64 when -fno-omit-frame-pointer is used). When fixed, the
    /// header specifies the fixed stack frame offset and the individual
    /// FREs do not track it. If not fixed this will return `None` and
    /// individual FREs will provide the applicable stack frame offset, if
    /// any.
    pub fn fixed_fp_offset(&self) -> Option<i8> {
        match self.fixed_fp_offset {
            0 => None,
            v => Some(v),
        }
    }

    /// Returns the fixed Return Address offset from the CFA, if any.
    ///
    /// The offset for the Return Address (RA) from CFA is fixed for some ABIs.
    /// When fixed, this field specifies the fixed stack frame offset and
    /// individual FREs do not track it. If not fixed then this method will
    /// return `None` and individual FREs will provide the applicable stack
    /// frame offset, if any.
    pub fn fixed_ra_offset(&self) -> Option<i8> {
        match self.fixed_ra_offset {
            0 => None,
            v => Some(v),
        }
    }

    pub fn num_fdes(&self) -> u32 {
        self.num_fdes
    }

    pub fn num_fres(&self) -> u32 {
        self.num_fres
    }

    /// Get an iterator over all the [FDEs] in this section.
    ///
    /// [FDEs]: FuncDescEntry
    pub fn fdes(&self) -> FuncDescIter<'a, O> {
        let inner = match self.fdes {
            FdeList::V1(slice) => FuncDescIterImpl::V1(slice.iter()),
            FdeList::V2(slice) => FuncDescIterImpl::V2(slice.iter()),
        };

        FuncDescIter {
            fdes: inner,
            fres: self.fres,
        }
    }

    /// Find the [`FuncDescEntry`] that is associated with the provided address.
    pub fn fde_for_address(&self, address: i32) -> Option<FuncDescEntry<'a, O>> {
        let mut iter = self.fdes();

        // Frames are not sorted so we need to do a linear search.
        if !self.flags().contains(Flags::FDE_SORTED) {
            return iter.find(|fde| fde.contains(address));
        }

        let index = match self.fdes {
            FdeList::V1(fdes) => fdes
                .binary_search_by(|fde| {
                    if address < fde.start_address.get() {
                        return Ordering::Less;
                    }

                    let reladdr = address - fde.start_address.get();
                    if reladdr as u32 >= fde.size.get() {
                        return Ordering::Greater;
                    }

                    Ordering::Equal
                })
                .ok()?,
            FdeList::V2(fdes) => fdes
                .binary_search_by(|fde| {
                    if address < fde.start_address.get() {
                        return Ordering::Less;
                    }

                    let reladdr = address - fde.start_address.get();
                    if reladdr as u32 >= fde.size.get() {
                        return Ordering::Greater;
                    }

                    Ordering::Equal
                })
                .ok()?,
        };

        let mut iter = self.fdes();
        iter.nth(index)
    }
}

impl<'a, O: ByteOrder> fmt::Debug for SFrame<'a, O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct DebugFdeList<'a, 'b, O: ByteOrder>(&'b SFrame<'a, O>);

        impl<'a, 'b, O: ByteOrder> fmt::Debug for DebugFdeList<'a, 'b, O> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list().entries(self.0.fdes()).finish()
            }
        }

        let mut dbg = f.debug_struct("SFrame");
        dbg.field("preamble", &self.preamble);
        dbg.field("abi_arch", &self.abi_arch);
        dbg.field("fixed_fp_offset", &self.fixed_fp_offset());
        dbg.field("fixed_ra_offset", &self.fixed_ra_offset());
        dbg.field("num_fdes", &self.num_fdes);
        dbg.field("num_fres", &self.num_fres);
        dbg.field("fdes", &DebugFdeList(self));
        dbg.finish()
    }
}

#[derive(Copy, Clone, Debug)]
enum FdeList<'a, O: ByteOrder> {
    V1(&'a [v1::FuncDescEntry<O>]),
    V2(&'a [v2::FuncDescEntry<O>]),
}

#[derive(Copy, Clone, Debug)]
enum Fde<'a, O: ByteOrder> {
    V1(&'a v1::FuncDescEntry<O>),
    V2(&'a v2::FuncDescEntry<O>),
}

impl<'a, O: ByteOrder> Fde<'a, O> {
    /// The start address of the function in virtual memory.
    pub fn start_address(&self) -> i32 {
        match self {
            Self::V1(fde) => fde.start_address.get(),
            Self::V2(fde) => fde.start_address.get(),
        }
    }

    /// The start address of the function in virtual memory.
    pub fn size(&self) -> u32 {
        match self {
            Self::V1(fde) => fde.size.get(),
            Self::V2(fde) => fde.size.get(),
        }
    }

    /// The offset in bytes of the function's first FRE.
    pub fn start_fre_off(&self) -> u32 {
        match self {
            Self::V1(fde) => fde.start_fre_off.get(),
            Self::V2(fde) => fde.start_fre_off.get(),
        }
    }

    /// The number of FREs used for this function.
    pub fn num_fres(&self) -> u32 {
        match self {
            Self::V1(fde) => fde.num_fres.get(),
            Self::V2(fde) => fde.num_fres.get(),
        }
    }

    pub fn info(&self) -> v2::FdeInfo {
        match self {
            Self::V1(fde) => fde.info,
            Self::V2(fde) => fde.info,
        }
    }

    pub fn rep_size(&self) -> Option<u8> {
        match self {
            Self::V1(_) => None,
            Self::V2(fde) => Some(fde.rep_size),
        }
    }

    pub fn fdetype(&self) -> FdeType {
        match self {
            Self::V1(fde) => match fde.info.fdetype() {
                v1::FdeType::PcInc => FdeType::PcInc,
                v1::FdeType::PcMask => FdeType::PcMaskV1,
            },
            Self::V2(fde) => match fde.info.fdetype() {
                v2::FdeType::PcInc => FdeType::PcInc,
                v2::FdeType::PcMask => FdeType::PcMask,
            },
        }
    }
}

/// Defines how the unwinder should find the matching FRE from the PC.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum FdeType {
    /// Unwinders should perform `PC >= FRE_START_ADDR` to look up a matching
    /// FRE.
    PcInc = 0,

    /// Unwinders should perform `PC % REP_BLOCK_SIZE >= FRE_START_ADDR` to look
    /// up a matchine FRE.
    PcMask = 1,

    /// Unwinders should perform
    /// ```text
    /// PC & FRE_START_ADDR_AS_MASK >= FRE_START_ADDR_AS_MASK
    /// ```
    /// to look up a matching FRE.
    ///
    /// This corresponds to the meaning of the `PCMASK` flag in the V1 SFrame
    /// specification. It will never be contained within a V2 SFrame section.
    PcMaskV1,
}

/// A SFrame function descriptor entry (FDE).
///
/// A FDE contains some general info about how to unwind the function along with
/// a sequence of [frame row entries][FrameRowEntry] (FREs). The FDE applies to
/// the whole function whereas individual FREs describe unwinding rules for
/// parts of the function.
pub struct FuncDescEntry<'a, O: ByteOrder = NativeEndian> {
    fde: Fde<'a, O>,
    fres: &'a [u8],
}

impl<'a, O: ByteOrder> FuncDescEntry<'a, O> {
    /// Return an iterator over all the [FREs] for this function.
    ///
    /// [FREs]: FrameRowEntry
    pub fn fres(&self) -> FrameRowIter<'a, O> {
        FrameRowIter::new(self.fde, self.fres)
    }

    /// The start address of the function in virtual memory.
    pub fn start_address(&self) -> i32 {
        self.fde.start_address()
    }

    /// The size of the function in bytes.
    pub fn size(&self) -> u32 {
        self.fde.size()
    }

    /// The strategy to use to find the matching FRE for a given PC.
    pub fn fdetype(&self) -> FdeType {
        self.fde.fdetype()
    }

    /// Specifies which key is used for signing the return addresses in the FDE.
    pub fn pauth_key(&self) -> v2::Aarch64PauthKey {
        self.fde.info().pauth_key()
    }

    /// The size of the repetitive block for which a FDE of type
    /// [`FdeType::PcMask`] is used.
    pub fn rep_block_size(&self) -> Option<u8> {
        self.fde.rep_size()
    }

    /// Returns whether this FDE contains the requested address.
    pub fn contains(&self, address: i32) -> bool {
        let start = self.start_address();
        if address < start {
            return false;
        }

        ((address - start) as u32) < self.size()
    }

    /// Attempt to find the [FRE] for the address within this function.
    ///
    /// Passing an address that is outside of the bounds of this function will
    /// return `None`.
    ///
    /// # Errors
    /// Returns an error if the [FREs][FRE] referred to by this FDE could not be
    /// parsed.
    ///
    /// [FRE]: FrameRowEntry
    pub fn get_fre_for_address(
        &self,
        address: i32,
    ) -> Result<Option<FrameRowEntry<'a, O>>, ReadError> {
        if address < self.start_address() {
            return Ok(None);
        }

        let relative = (address - self.start_address()) as u32;
        if relative > self.size() {
            return Ok(None);
        }

        match self.fdetype() {
            FdeType::PcInc => {
                for fre in self.fres() {
                    let fre = fre?;

                    if relative >= fre.start_address_offset() {
                        return Ok(Some(fre));
                    }
                }
            }
            FdeType::PcMask => {
                let rep_block_size = self.rep_block_size().unwrap() as u32;
                if rep_block_size == 0 {
                    return Err(ReadError::InvalidFdeRepBlockSize);
                }

                let modrel = relative % rep_block_size;
                for fre in self.fres() {
                    let fre = fre?;

                    if modrel >= fre.start_address_offset() {
                        return Ok(Some(fre));
                    }
                }
            }
            FdeType::PcMaskV1 => {
                for fre in self.fres() {
                    let fre = fre?;
                    let mask = fre.start_address_offset();

                    if relative & mask >= mask {
                        return Ok(Some(fre));
                    }
                }
            }
        }

        Ok(None)
    }
}

impl<'a, O: ByteOrder> fmt::Debug for FuncDescEntry<'a, O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut dbg = f.debug_struct("FuncDescEntry");

        match &self.fde {
            Fde::V1(fde) => {
                dbg.field(
                    "start_address",
                    &format_args!("{:#x}", fde.start_address.get()),
                );
                dbg.field("size", &fde.size.get());
                dbg.field("fdetype", &fde.info.fdetype());
                dbg.field("pauth_key", &fde.info.pauth_key());
                dbg.field("num_fres", &fde.num_fres.get());
                dbg.field("start_fre_off", &fde.start_fre_off.get());
            }
            Fde::V2(fde) => {
                dbg.field(
                    "start_address",
                    &format_args!("{:#x}", fde.start_address.get()),
                );
                dbg.field("size", &fde.size.get());
                dbg.field("fdetype", &fde.info.fdetype());
                dbg.field("pauth_key", &fde.info.pauth_key());
                dbg.field("rep_size", &fde.rep_size);
                dbg.field("num_fres", &fde.num_fres.get());
                dbg.field("start_fre_off", &fde.start_fre_off.get());
            }
        }

        struct DebugFreList<'a, 'b, O: ByteOrder>(&'b FuncDescEntry<'a, O>);

        impl<'a, 'b, O: ByteOrder> fmt::Debug for DebugFreList<'a, 'b, O> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list().entries(self.0.fres()).finish()
            }
        }

        dbg.field("fres", &DebugFreList(self));
        dbg.finish()
    }
}

/// A SFrame frame row entry (FRE).
///
/// A FRE contains the core of the stack trace information. It describes how to
/// recover the CFA, RA, and FP from the stack frame when the IP falls within a
/// range of instructions.
///
/// Once you have both the FRE and FDE for a given program counter (PC), you can
/// get the PC for the previous frame (RA) and FP by doing the following:
/// - `CFA = BASE_REG + fre.cfa_offset()?` (`BASE_REG` may be either `SP` or
///   `FP` depending on the return value of [`cfa_base_reg_id`]).
/// - `RA = CFA + fre.ra_offset(&sframe)?`
/// - `FP = CFA + fre.fp_offset(&sframe)?`
///
/// [`cfa_base_reg_id`]: FrameRowEntry::cfa_base_reg_id
#[derive(Clone)]
pub struct FrameRowEntry<'a, O: ByteOrder = NativeEndian> {
    fde: Fde<'a, O>,

    start_address_offset: u32,
    info: v2::FreInfo,
    offsets: [i32; 3],
}

impl<'a, O: ByteOrder> FrameRowEntry<'a, O> {
    fn load(fde: Fde<'a, O>, fres: &'a [u8]) -> Result<(Self, &'a [u8]), ReadError> {
        let (start_address, info, offsets) = match fde.info().fretype() {
            v2::FreType::Addr1 => {
                let fre = v2::FrameRowEntry::<u8>::ref_from_prefix(fres)
                    .ok_or(ReadError::UnexpectedEof)?;
                let offsets = fres
                    .get(mem::size_of_val(fre)..)
                    .ok_or(ReadError::UnexpectedEof)?;

                (fre.start_address as u32, fre.info, offsets)
            }
            v2::FreType::Addr2 => {
                let fre = v2::FrameRowEntry::<U16<O>>::ref_from_prefix(fres)
                    .ok_or(ReadError::UnexpectedEof)?;
                let offsets = fres
                    .get(mem::size_of_val(fre)..)
                    .ok_or(ReadError::UnexpectedEof)?;

                (fre.start_address.get() as u32, fre.info, offsets)
            }
            v2::FreType::Addr4 => {
                let fre = v2::FrameRowEntry::<U32<O>>::ref_from_prefix(fres)
                    .ok_or(ReadError::UnexpectedEof)?;
                let offsets = fres
                    .get(mem::size_of_val(fre)..)
                    .ok_or(ReadError::UnexpectedEof)?;

                (fre.start_address.get(), fre.info, offsets)
            }

            ty => return Err(ReadError::UnsupportedFreType(ty)),
        };

        if !(0..=3).contains(&info.offset_count()) {
            return Err(ReadError::InvalidFreOffsetCount(info.offset_count()));
        }

        let remaining_fres;
        let count = info.offset_count() as usize;
        let offsets: [i32; 3] = match info.offset_size() {
            v2::FreOffset::_1B => {
                let (offsets, rest) =
                    i8::slice_from_prefix(offsets, count).ok_or(ReadError::UnexpectedEof)?;
                let offsets = offsets.get(..count).ok_or(ReadError::UnexpectedEof)?;

                remaining_fres = rest;

                array::from_fn(|i| match offsets.get(i).copied() {
                    Some(offset) => offset.into(),
                    None => 0,
                })
            }
            v2::FreOffset::_2B => {
                let (offsets, rest) =
                    <I16<O>>::slice_from_prefix(offsets, count).ok_or(ReadError::UnexpectedEof)?;
                let offsets = offsets.get(..count).ok_or(ReadError::UnexpectedEof)?;

                remaining_fres = rest;

                array::from_fn(|i| match offsets.get(i).copied() {
                    Some(offset) => offset.get().into(),
                    None => 0,
                })
            }
            v2::FreOffset::_4B => {
                let (offsets, rest) =
                    <I32<O>>::slice_from_prefix(offsets, count).ok_or(ReadError::UnexpectedEof)?;
                let offsets = offsets.get(..count).ok_or(ReadError::UnexpectedEof)?;

                remaining_fres = rest;

                array::from_fn(|i| match offsets.get(i).copied() {
                    Some(offset) => offset.get(),
                    None => 0,
                })
            }

            ty => return Err(ReadError::UnsupportedFreOffset(ty)),
        };

        assert!(
            start_address < fde.size(),
            "Invalid FRE start address for FDE for {:#x} ({start_address} >= {})",
            fde.start_address(),
            fde.size()
        );

        let fre = Self {
            fde,
            start_address_offset: start_address,
            info,
            offsets,
        };

        Ok((fre, remaining_fres))
    }

    /// The start address of this FRE.
    pub fn start_address(&self) -> i32 {
        if cfg!(debug_assertions) {
            self.fde
                .start_address()
                .checked_add_unsigned(self.start_address_offset)
                .expect("addition overflowed")
        } else {
            self.fde
                .start_address()
                .wrapping_add_unsigned(self.start_address_offset)
        }
    }

    /// The offset of the start address of this FRE from the start address
    /// specified in its parent FDE.
    pub fn start_address_offset(&self) -> u32 {
        self.start_address_offset
    }

    fn offsets(&self) -> &[i32] {
        let count = self.info.offset_count();
        match self.offsets.get(..count as usize) {
            Some(offsets) => offsets,
            None => &self.offsets,
        }
    }

    /// Read the register offset for the CFA.
    pub fn cfa_offset(&self) -> Result<i32, ReadError> {
        self.offsets()
            .get(0)
            .copied()
            .ok_or(ReadError::MissingFreOffset)
    }

    /// Read the register offset for the RA.
    pub fn ra_offset(&self, sframe: &SFrame<'a, O>) -> Result<i32, ReadError> {
        match sframe.fixed_ra_offset() {
            Some(offset) => Ok(offset.into()),
            None => self
                .offsets()
                .get(1)
                .copied()
                .ok_or(ReadError::MissingFreOffset),
        }
    }

    /// Read the register offset for the FP.
    pub fn fp_offset(&self, sframe: &SFrame<'a, O>) -> Result<i32, ReadError> {
        match sframe.fixed_fp_offset() {
            Some(offset) => Ok(offset.into()),
            None => {
                let index = match sframe.fixed_ra_offset() {
                    Some(_) => 1,
                    None => 2,
                };

                self.offsets()
                    .get(index)
                    .copied()
                    .ok_or(ReadError::MissingFreOffset)
            }
        }
    }

    /// Distinguish between SP or FP based CFA recovery.
    pub fn cfa_base_reg_id(&self) -> v2::FreBaseRegId {
        self.info.cfa_base_reg_id()
    }

    /// Indicates whether the return address is mangled with any authorization
    /// bits (for signed RA).
    pub fn mangled_ra_p(&self) -> bool {
        self.info.mangled_ra_p()
    }
}

impl<'a, O: ByteOrder> fmt::Debug for FrameRowEntry<'a, O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let offsets = &self.offsets[..self.info.offset_count().min(3) as usize];
        let mut dbg = f.debug_struct("FrameRowEntry");
        dbg.field("start_address", &self.start_address_offset);
        dbg.field("cfa_base_reg_id", &self.info.cfa_base_reg_id());
        dbg.field("mangled_ra_p", &self.mangled_ra_p());
        dbg.field("offsets", &offsets);
        dbg.finish()
    }
}

/// An iterator over all [`FuncDescEntry`] items within a [`SFrame`].
#[derive(Clone)]
pub struct FuncDescIter<'a, O: ByteOrder = NativeEndian> {
    fdes: FuncDescIterImpl<'a, O>,
    fres: &'a [u8],
}

#[derive(Clone)]
enum FuncDescIterImpl<'a, O: ByteOrder = NativeEndian> {
    V1(core::slice::Iter<'a, v1::FuncDescEntry<O>>),
    V2(core::slice::Iter<'a, v2::FuncDescEntry<O>>),
}

impl<'a, O: ByteOrder> Iterator for FuncDescIter<'a, O> {
    type Item = FuncDescEntry<'a, O>;

    fn next(&mut self) -> Option<Self::Item> {
        let fde = match &mut self.fdes {
            FuncDescIterImpl::V1(iter) => Fde::V1(iter.next()?),
            FuncDescIterImpl::V2(iter) => Fde::V2(iter.next()?),
        };
        let offset = fde.start_fre_off() as usize;

        // This will fail when the user attempts to read the FREs if the offset is
        // invalid.
        let fres = self.fres.get(offset..).unwrap_or_default();

        Some(FuncDescEntry { fde, fres })
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        let fde = match &mut self.fdes {
            FuncDescIterImpl::V1(iter) => Fde::V1(iter.nth(n)?),
            FuncDescIterImpl::V2(iter) => Fde::V2(iter.nth(n)?),
        };

        Some(FuncDescEntry {
            fde,
            fres: self.fres,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.fdes {
            FuncDescIterImpl::V1(iter) => iter.size_hint(),
            FuncDescIterImpl::V2(iter) => iter.size_hint(),
        }
    }
}

impl<'a, O: ByteOrder> DoubleEndedIterator for FuncDescIter<'a, O> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let fde = match &mut self.fdes {
            FuncDescIterImpl::V1(iter) => Fde::V1(iter.next_back()?),
            FuncDescIterImpl::V2(iter) => Fde::V2(iter.next_back()?),
        };

        Some(FuncDescEntry {
            fde,
            fres: self.fres,
        })
    }
}

impl<'a, O: ByteOrder> FusedIterator for FuncDescIter<'a, O> {}
impl<'a, O: ByteOrder> ExactSizeIterator for FuncDescIter<'a, O> {}

/// An iterator over all [`FrameRowEntry`] items for a [`FuncDescEntry`].
#[derive(Clone)]
pub struct FrameRowIter<'a, O: ByteOrder = NativeEndian> {
    fde: Fde<'a, O>,
    fres: &'a [u8],
    index: u32,
}

impl<'a, O: ByteOrder> FrameRowIter<'a, O> {
    fn new(fde: Fde<'a, O>, fres: &'a [u8]) -> Self {
        Self {
            fde,
            fres,
            index: 0,
        }
    }
}

impl<'a, O: ByteOrder> Iterator for FrameRowIter<'a, O> {
    type Item = Result<FrameRowEntry<'a, O>, ReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.fde.num_fres() {
            return None;
        }

        Some(match FrameRowEntry::load(self.fde, self.fres) {
            Ok((fre, rest)) => {
                self.index += 1;
                self.fres = rest;

                Ok(fre)
            }
            Err(e) => {
                self.index = u32::MAX;

                Err(e)
            }
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.index >= self.fde.num_fres() {
            return (0, Some(0));
        }

        let bound = (self.fde.num_fres() - self.index) as usize;
        (1.min(bound), Some(bound))
    }
}

impl<'a, O: ByteOrder> FusedIterator for FrameRowIter<'a, O> {}
