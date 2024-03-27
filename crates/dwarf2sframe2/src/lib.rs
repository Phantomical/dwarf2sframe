//! Convert `.eh_header` DWARF debug info into [SFrame] unwind info.
//!
//! [SFrame]: https://sourceware.org/binutils/docs/sframe-spec.html

use std::collections::HashMap;
use std::fmt;

use elf_sframe::raw::v2::{self, FreBaseRegId};
use elf_sframe::write::{FrameRowBuilder, FrameRowOffsets, FuncDescBuilder, SFrameOptions};
use gimli::{EhFrame, Endianity, RunTimeEndian, Section, UnwindSection};

use crate::display::{DisplayRegister, RegisterRule};

pub extern crate gimli;

mod display;
mod dump;
mod error;

pub use elf_sframe::write::SFrameBuilder;
pub use gimli::RunTimeEndian as Endian;

pub use crate::error::Error;

pub struct Options {
    arch: Architecture,
    merge_fres: bool,
    merge_fdes: bool,
    warnings: bool,
    debugdump: bool,
    endian: Option<Endian>,
    bases: gimli::BaseAddresses,
}

impl Options {
    pub fn new(arch: Architecture, bases: gimli::BaseAddresses) -> Self {
        Self {
            arch,
            merge_fdes: true,
            merge_fres: true,
            warnings: false,
            debugdump: false,
            endian: None,
            bases,
        }
    }

    /// Merge identical consective frame row entries within a function.
    ///
    /// If set to false, then the generated sframes will exactly match the
    /// individual unwinding rows specified in the DWARF unwind tables.
    ///
    /// Defaults to true.
    pub fn merge_fres(mut self, merge: bool) -> Self {
        self.merge_fres = merge;
        self
    }

    /// Merge identical consecutive function descriptor entries.
    ///
    /// The SFrame format allows a function descriptor entry to cover multiple
    /// chunks of code that have identical unwind info. If set to true, then
    /// consecutive FDEs will be merged into one repeated (PcMask) FDE.
    ///
    /// Defaults to true.
    pub fn merge_fdes(mut self, merge: bool) -> Self {
        self.merge_fdes = merge;
        self
    }

    /// Explicitly set the endian used as part of the ABI/arch identifier.
    ///
    /// If not set then this will be inferred from the endianness of the
    /// provided [`EhFrame`] section.
    pub fn endian(mut self, endian: impl Into<Option<Endian>>) -> Self {
        self.endian = endian.into();
        self
    }

    /// Set the architecture to be set in the in the SFrame header.
    ///
    /// This will be combined with [`endian`] to produce the final ABI/arch
    /// identifier stored within the generated section.
    ///
    /// [`endian`]: Options::endian
    pub fn arch(mut self, arch: Architecture) -> Self {
        self.arch = arch;
        self
    }

    /// Set the base addresses used to determine the addresses of symbols.
    pub fn bases(mut self, bases: gimli::BaseAddresses) -> Self {
        self.bases = bases;
        self
    }

    /// Dump the dwarf FDEs as they are processed.
    pub fn debugdump(mut self, dump: bool) -> Self {
        self.debugdump = dump;
        self
    }

    pub fn warnings(mut self, warnings: bool) -> Self {
        self.warnings = warnings;
        self
    }
}

/// A CPU architecture.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub enum Architecture {
    Amd64,
    Aarch64,
}

impl Architecture {
    fn fp(&self) -> gimli::Register {
        match self {
            Self::Amd64 => gimli::X86_64::RBP,
            Self::Aarch64 => gimli::AArch64::X29,
        }
    }

    fn sp(&self) -> gimli::Register {
        match self {
            Self::Amd64 => gimli::X86_64::RSP,
            Self::Aarch64 => gimli::AArch64::SP,
        }
    }

    fn ra(&self) -> gimli::Register {
        match self {
            Self::Amd64 => gimli::X86_64::RA,

            // See https://developer.arm.com/documentation/dui0801/l/Overview-of-AArch64-state/Link-registers
            Self::Aarch64 => gimli::AArch64::X30,
        }
    }
}

pub fn dwarf2sframe<R: gimli::Reader>(
    eh_frame: EhFrame<R>,
    options: &Options,
) -> Result<SFrameBuilder, Error> {
    let endian = match eh_frame.reader().endian().is_big_endian() {
        true => RunTimeEndian::Big,
        false => RunTimeEndian::Little,
    };

    let abi = match (options.arch, options.endian.unwrap_or(endian)) {
        (Architecture::Aarch64, Endian::Little) => v2::Abi::AARCH64_ENDIAN_LITTLE,
        (Architecture::Aarch64, Endian::Big) => v2::Abi::AARCH64_ENDIAN_BIG,
        (Architecture::Amd64, Endian::Little) => v2::Abi::AMD64_ENDIAN_LITTLE,
        _ => v2::Abi::INVALID,
    };

    let mut sfoptions = SFrameOptions::new().abi(abi);
    if abi == v2::Abi::AMD64_ENDIAN_LITTLE {
        // Amd64 always has the return address at CFA-8. This is due to how
        // the call instruction works on x86.
        sfoptions = sfoptions.fixed_ra_offset(-8);
    }

    let mut dwarf2sframe = Dwarf2SFrame {
        options: &options,
        sframe: SFrameBuilder::new(sfoptions),
    };

    dwarf2sframe.convert(&eh_frame)?;

    let mut sframe = dwarf2sframe.sframe;
    if options.merge_fdes {
        sframe.merge_adjacent_fdes()
    }

    Ok(sframe)
}

struct Dwarf2SFrame<'a> {
    options: &'a Options,
    sframe: SFrameBuilder,
}

impl<'a> Dwarf2SFrame<'a> {
    fn convert<R: gimli::Reader>(&mut self, eh_frame: &EhFrame<R>) -> Result<(), Error> {
        let mut entries = eh_frame.entries(&self.options.bases);
        let mut cies = HashMap::new();
        let mut ctx = gimli::UnwindContext::new();

        while let Some(entry) = entries.next().map_err(Error::InvalidEhFrameEntry)? {
            let fde = match entry {
                gimli::CieOrFde::Cie(_) => continue,
                gimli::CieOrFde::Fde(partial) => partial
                    .parse(|_section, bases, offset| {
                        cies.entry(offset)
                            .or_insert_with(|| eh_frame.cie_from_offset(bases, offset))
                            .clone()
                    })
                    .map_err(Error::InvalidDwarfFde)?,
            };

            let start_address = fde.initial_address();
            let len = fde.len();

            if self.options.debugdump {
                println!("FDE:");
                println!(" start_address: {start_address:#010x}");
                println!(
                    "    range_size: {len:#010x} (end_addr = {:#010x})",
                    start_address + len
                );

                crate::dump::dump_cfi_instructions(
                    &mut std::io::stdout().lock(),
                    fde.instructions(eh_frame, &self.options.bases),
                    self.options.arch,
                    fde.cie().encoding(),
                )
                .map_err(Error::InvalidDwarfFde)?;
                println!();
                println!("Rows:");
            }

            if start_address > i32::MAX as u64 {
                return Err(Error::InvalidStartAddress {
                    address: start_address,
                });
            }

            if len > i32::MAX as u64 {
                return Err(Error::InvalidFunctionLength {
                    address: start_address,
                    len,
                });
            }

            let mut sfde =
                FuncDescBuilder::new(self.sframe.options(), start_address as i32, len as u32);
            let mut rows = fde
                .rows(eh_frame, &self.options.bases, &mut ctx)
                .map_err(Error::InvalidUnwindTable)?;

            while let Some(row) = rows.next_row().map_err(Error::InvalidUnwindTable)? {
                if self.options.debugdump {
                    println!(
                        "  - offset: {:#010x} (end = {:#010x})",
                        row.start_address(),
                        row.end_address()
                    );
                    match row.cfa() {
                        &gimli::CfaRule::RegisterAndOffset { register, offset } => println!(
                            "    cfa:    {}{:+}",
                            DisplayRegister::new(self.options.arch, register),
                            offset
                        ),
                        gimli::CfaRule::Expression(expr) => println!("    cfa:    {expr:?}"),
                    }

                    for (reg, rule) in row.registers() {
                        println!(
                            "    reg:    {} = {}",
                            DisplayRegister::new(self.options.arch, *reg),
                            RegisterRule::new(rule, self.options.arch)
                        );
                    }
                }

                if row.start_address() == row.end_address() {
                    // Some binaries have zero-width rows in their debug info. This can result in us
                    // generating an invalid FRE whose start offset is >= fde.len. Avoid this by
                    // skipping such entries. They cannot affect unwinding so it is safe to do so.
                    continue;
                }

                let row_start = match u32::try_from(row.start_address() - start_address) {
                    Ok(addr) if addr < i32::MAX as u32 => addr as u32,
                    _ => {
                        return Err(Error::InvalidRowOffset {
                            address: row.start_address(),
                            offset: row.start_address() - start_address,
                        })
                    }
                };

                let fre = match self.convert_row(start_address, row) {
                    Ok(fre) => fre,
                    Err(ConvertRowError::Warning(warning)) => {
                        if self.options.warnings {
                            eprintln!("warning: {warning}");
                        }

                        FrameRowBuilder::invalid(row_start)
                    }
                    Err(ConvertRowError::Fatal(error)) => return Err(error),
                };

                // println!("    fre:    {fre:#x?}");
                if let Err(e) = sfde.row(fre) {
                    panic!(
                        "Generated SFrame FDE for DWARF FDE at {start_address:#x} was invalid: {e}"
                    )
                }
            }

            if self.options.merge_fres {
                sfde.merge_adjacent_fres();
            }

            self.sframe.fde(sfde);

            if self.options.debugdump {
                println!();
            }
        }

        Ok(())
    }

    fn convert_row<R: gimli::Reader>(
        &mut self,
        start_address: u64,
        row: &gimli::UnwindTableRow<R>,
    ) -> Result<FrameRowBuilder, ConvertRowError> {
        let fp = self.options.arch.fp();
        let sp = self.options.arch.sp();
        let ra = self.options.arch.ra();

        let (base, offset) = match row.cfa() {
            &gimli::CfaRule::RegisterAndOffset { register, offset } => match register {
                reg if reg == sp => (FreBaseRegId::Sp, offset),
                reg if reg == fp => (FreBaseRegId::Fp, offset),
                reg => {
                    return Err(self.warn(format_args!(
                        "FDE for {start_address:#010x}: unsupported CFA source register `{}`",
                        DisplayRegister::new(self.options.arch, reg)
                    )));
                }
            },
            gimli::CfaRule::Expression(_) => {
                return Err(self.warn(format_args!(
                    "FDE for {start_address:#010x}: CFA recovery rule requires evaluating a DWARF \
                     expression",
                )));
            }
        };

        let row_start = match u32::try_from(row.start_address() - start_address) {
            Ok(addr) if addr < i32::MAX as u32 => addr as u32,
            _ => {
                return Err(ConvertRowError::Fatal(Error::InvalidRowOffset {
                    address: row.start_address(),
                    offset: row.start_address() - start_address,
                }))
            }
        };

        let offset = match i32::try_from(offset) {
            Ok(offset) => offset,
            Err(_) => {
                return Err(self.warn(format_args!(
                    "FDE for {start_address:#010x}: CFA register offset {offset:#x} too large to \
                     be represented in the SFrame format"
                )));
            }
        };

        let fp_offset = match row.register(fp) {
            gimli::RegisterRule::Offset(offset) => {
                let offset = i32::try_from(offset).map_err(|_| {
                    self.warn(format_args!(
                        "FDE for {start_address:#010x}: FP register offset {offset:#x} too large \
                         to represented in the SFrame format"
                    ))
                })?;

                Some(offset)
            }
            gimli::RegisterRule::SameValue => None,
            gimli::RegisterRule::Undefined => None,
            rule => {
                return Err(self.warn(format_args!(
                    "FDE for {start_address:#010x}: Unsupport FP recovery rule: `{}`",
                    RegisterRule::new(&rule, self.options.arch)
                )))
            }
        };

        let ra_offset = match row.register(ra) {
            gimli::RegisterRule::Offset(offset) => {
                let offset = i32::try_from(offset).map_err(|_| {
                    self.warn(format_args!(
                        "FDE for {start_address:#010x}: RA register offset {offset:#x} too large \
                         to represented in the SFrame format"
                    ))
                })?;

                offset
            }
            rule => {
                return Err(self.warn(format_args!(
                    "FDE for {start_address:#010x}: Unsupport RA recovery rule: `{}`",
                    RegisterRule::new(&rule, self.options.arch)
                )))
            }
        };

        let offsets = FrameRowOffsets {
            cfa: offset,
            fp: fp_offset,
            ra: Some(ra_offset),
        };

        Ok(FrameRowBuilder::new(base, row_start, offsets))
    }

    fn warn<M>(&self, message: M) -> ConvertRowError
    where
        M: fmt::Display,
    {
        let message = match self.options.warnings {
            true => message.to_string(),
            false => String::new(),
        };

        ConvertRowError::Warning(message)
    }
}

enum ConvertRowError {
    Fatal(Error),
    Warning(String),
}

impl From<Error> for ConvertRowError {
    fn from(error: Error) -> Self {
        Self::Fatal(error)
    }
}
