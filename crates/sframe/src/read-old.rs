use std::cmp::Ordering;
use std::mem;

use zerocopy::{ByteOrder, FromBytes, U16, U32};

use crate::raw::*;


/// The overall accessor for the SFrame format.
pub struct SFrameV2<'a, O: ByteOrder> {
    /// A reference to the header itself.
    header: &'a v2::Header<O>,

    /// Data contained within the auxiliary header.
    ///
    /// There is nothing in the specification that uses this at the moment but
    /// we keep it to remain forward-compatible.
    aux: &'a [u8],

    /// An array containing all FDEs within the format.
    fdes: &'a [v2::FuncDescEntry<O>],

    /// A slice to the FRE section.
    ///
    /// The format of FREs isn't uniform (or aligned) enough to be represented
    /// as a higher-level construct so we just use a byte slice here.
    fres: &'a [u8],
}

impl<'a, O: ByteOrder> SFrameV2<'a, O> {
    pub fn load(section: &'a [u8]) -> Result<Self, ParseError> {
        assert!(
            section.as_ptr() as usize % 4 != 0,
            "section data was not 4-byte aligned"
        );

        let preamble = match Preamble::<O>::ref_from_prefix(section) {
            Some(preamble) => preamble,
            None => return Err(ParseError::UnexpectedEof),
        };

        if preamble.version != Version::V2 {
            return Err(ParseError::UnsupportedVersion(preamble.version.0));
        }

        if preamble.magic.get() != MAGIC {
            return Err(ParseError::IncorrectEndian);
        }

        let header = match v2::Header::<O>::ref_from_prefix(section) {
            Some(header) => header,
            None => return Err(ParseError::UnexpectedEof),
        };

        let data = &section[mem::size_of_val(header)..];
        let aux = match data.get(..header.auxhdr_len as usize) {
            Some(aux) => aux,
            None => return Err(ParseError::UnexpectedEof),
        };

        let fdes = match data.get(
            (header.fdeoff.get() as usize)
                ..(header.num_fdes.get() as usize * mem::size_of::<v2::FuncDescEntry<O>>()),
        ) {
            Some(fdes) => match v2::FuncDescEntry::<O>::slice_from(fdes) {
                Some(fdes) => fdes,
                None => unreachable!("unable to convert slice to FDE slice"),
            },
            None => return Err(ParseError::UnexpectedEof),
        };

        let fres = match data.get((header.freoff.get() as usize)..(header.fre_len.get() as usize)) {
            Some(fres) => fres,
            None => return Err(ParseError::UnexpectedEof),
        };

        Ok(Self {
            header,
            aux,
            fdes,
            fres,
        })
    }

    pub fn header(&self) -> &'a v2::Header<O> {
        self.header
    }

    /// Directly access the bytes that make up the aux header.
    /// 
    /// Currently there is nothing that specifies what 
    pub fn raw_aux(&self) -> &'a [u8] {
        self.aux
    }

    pub fn get_fde_by_index(&self, index: usize) -> Result<FuncDescEntry<'a, O>, ParseError> {
        let fde = self.fdes.get(index).ok_or(ParseError::InvalidFdeIndex)?;
        let fres = self
            .fres
            .get(fde.start_fre_off.get() as usize..)
            .ok_or(ParseError::UnexpectedEof)?;

        Ok(FuncDescEntry { fde, fres })
    }

    pub fn get_fde_by_address(
        &self,
        address: i32,
    ) -> Result<Option<FuncDescEntry<'a, O>>, ParseError> {
        let index = self.fdes.binary_search_by(|fde| {
            if address < fde.start_address.get() {
                return Ordering::Less;
            }

            if fde.start_address.get() + (fde.size.get() as i32) <= address {
                return Ordering::Greater;
            }

            Ordering::Equal
        });

        let index = match index {
            Ok(index) => index,
            Err(_) => return Ok(None),
        };

        self.get_fde_by_index(index).map(Some)
    }
}

pub struct FuncDescEntry<'a, O: ByteOrder> {
    fde: &'a v2::FuncDescEntry<O>,
    fres: &'a [u8],
}

impl<'a, O: ByteOrder> FuncDescEntry<'a, O> {
    pub fn as_raw(&self) -> &'a v2::FuncDescEntry<O> {
        self.fde
    }

    pub fn fres(&self) -> FrameRowEntryIter<'a, O> {
        FrameRowEntryIter {
            fde: self.fde,
            fres: self.fres,
            index: 0,
        }
    }

    /// The start address of the function in virtual memory.
    pub fn start_address(&self) -> i32 {
        self.fde.start_address.get()
    }

    /// The size of the function in bytes.
    pub fn size(&self) -> u32 {
        self.fde.size.get()
    }

    /// The offset in bytes of the function's first FRE.
    pub fn start_fre_off(&self) -> u32 {
        self.fde.start_fre_off.get()
    }

    /// The number of FREs used for this function.
    pub fn num_fres(&self) -> u32 {
        self.fde.num_fres.get()
    }

    /// The type of the FRE frames for this FDE.
    pub fn fretype(&self) -> v2::FreType {
        self.fde.fretype()
    }

    /// The type of address computation used to determine which FRE applies for
    /// a PC.
    pub fn fdetype(&self) -> v2::FdeType {
        self.fde.fdetype()
    }

    /// Specifies which key is used for signing the return addresses in the FDE.
    pub fn pauth_key(&self) -> v2::Aarch64PauthKey {
        self.fde.pauth_key()
    }
}

pub struct FrameRowEntry<'a, O: ByteOrder> {
    fde: &'a v2::FuncDescEntry<O>,

    start_address: u32,
    info: v2::FreInfo,
    offsets: [u32; 3],
}

impl<'a, O: ByteOrder> FrameRowEntry<'a, O> {
    fn new(fde: &'a v2::FuncDescEntry<O>, fres: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (start_address, info, offsets) = match fde.fretype() {
            v2::FreType::Addr1 => {
                let fre = v2::FrameRowEntry::<u8>::ref_from_prefix(fres)
                    .ok_or(ParseError::UnexpectedEof)?;
                let offsets = fres
                    .get(mem::size_of_val(fre)..)
                    .ok_or(ParseError::UnexpectedEof)?;

                (fre.start_address as u32, fre.info, offsets)
            }
            v2::FreType::Addr2 => {
                let fre = v2::FrameRowEntry::<U16<O>>::ref_from_prefix(fres)
                    .ok_or(ParseError::UnexpectedEof)?;
                let offsets = fres
                    .get(mem::size_of_val(fre)..)
                    .ok_or(ParseError::UnexpectedEof)?;

                (fre.start_address.get() as u32, fre.info, offsets)
            }
            v2::FreType::Addr4 => {
                let fre = v2::FrameRowEntry::<U32<O>>::ref_from_prefix(fres)
                    .ok_or(ParseError::UnexpectedEof)?;
                let offsets = fres
                    .get(mem::size_of_val(fre)..)
                    .ok_or(ParseError::UnexpectedEof)?;

                (fre.start_address.get(), fre.info, offsets)
            }

            ty => return Err(ParseError::UnsupportedFreType(ty)),
        };

        if info.offset_count() > 3 {
            return Err(ParseError::InvalidFreOffsetCount(info.offset_count()));
        }

        let remaining_fres;
        let count = info.offset_count() as usize;
        let offsets: [u32; 3] = match info.offset_size() {
            v2::FreOffset::_1B => {
                let (offsets, rest) =
                    u8::slice_from_prefix(offsets, count).ok_or(ParseError::UnexpectedEof)?;
                let offsets = offsets.get(..count).ok_or(ParseError::UnexpectedEof)?;

                remaining_fres = rest;

                std::array::from_fn(|i| match offsets.get(i).copied() {
                    Some(offset) => offset as u32,
                    None => 0,
                })
            }
            v2::FreOffset::_2B => {
                let (offsets, rest) =
                    <U16<O>>::slice_from_prefix(offsets, count).ok_or(ParseError::UnexpectedEof)?;
                let offsets = offsets.get(..count).ok_or(ParseError::UnexpectedEof)?;

                remaining_fres = rest;

                std::array::from_fn(|i| match offsets.get(i).copied() {
                    Some(offset) => offset.get() as u32,
                    None => 0,
                })
            }
            v2::FreOffset::_4B => {
                let (offsets, rest) =
                    <U32<O>>::slice_from_prefix(offsets, count).ok_or(ParseError::UnexpectedEof)?;
                let offsets = offsets.get(..count).ok_or(ParseError::UnexpectedEof)?;

                remaining_fres = rest;

                std::array::from_fn(|i| match offsets.get(i).copied() {
                    Some(offset) => offset.get() as u32,
                    None => 0,
                })
            }

            ty => return Err(ParseError::UnsupportedFreOffset(ty)),
        };

        let fre = Self {
            fde,
            start_address,
            info,
            offsets,
        };

        Ok((fre, remaining_fres))
    }
}

pub struct FrameRowEntryIter<'a, O: ByteOrder> {
    fde: &'a v2::FuncDescEntry<O>,
    fres: &'a [u8],
    index: usize,
}

impl<'a, O: ByteOrder> Iterator for FrameRowEntryIter<'a, O> {
    type Item = Result<FrameRowEntry<'a, O>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.fde.num_fres.get() as _ {
            return None;
        }

        match FrameRowEntry::new(self.fde, self.fres) {
            Ok((fre, rest)) => {
                self.fres = rest;
                self.index += 1;

                Some(Ok(fre))
            }
            Err(e) => {
                self.index = usize::MAX;

                Some(Err(e))
            }
        }
    }
}

pub enum ParseError {
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
}
