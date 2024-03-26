use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use elf_sframe::raw::v2::{Abi, FreBaseRegId};
use elf_sframe::write::{
    FrameRowBuilder, FrameRowOffsets, FuncDescBuilder, SFrameBuilder, SFrameOptions,
};
use elf_sframe::NativeEndian;
use gimli::UnwindSection;
use object::{Endianness, Object, ObjectSection};

mod dump;
mod fmthelp;

use crate::dump::dump_cfi_instructions;
use crate::fmthelp::RegisterRule;

#[derive(Debug, clap::Parser)]
struct Args {
    input: PathBuf,

    #[arg(long, short)]
    output: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let path = args.input;

    let file = File::open(&path).with_context(|| format!("failed to open `{}`", path.display()))?;
    let data = unsafe { memmap2::Mmap::map(&file) }
        .with_context(|| format!("failed to mmap `{}`", path.display()))?;
    let file = object::File::parse(&*data)
        .with_context(|| format!("failed to parse `{}`", path.display()))?;
    let endian = match file.endianness() {
        Endianness::Big => gimli::RunTimeEndian::Big,
        Endianness::Little => gimli::RunTimeEndian::Little,
    };

    let section = match file.section_by_name(".eh_frame") {
        Some(section) => section,
        None => anyhow::bail!("elf binary has no .eh_frame section"),
    };
    let data = section
        .uncompressed_data()
        .context("failed to decompress the .eh_frame section")?;

    let eh_frame = gimli::EhFrame::new(&data, endian);

    let options = SFrameOptions::new()
        .abi(Abi::AMD64_ENDIAN_LITTLE)
        // .fixed_ra_offset(-8);
        ;
    let mut sframe = SFrameBuilder::new(options);

    let mut bases = gimli::BaseAddresses::default();
    if let Some(section) = file.section_by_name(".eh_frame_hdr") {
        println!(".eh_frame_hdr: {:#010x}", section.address());
        bases = bases.set_eh_frame_hdr(section.address());
    }

    if let Some(section) = file.section_by_name(".eh_frame") {
        println!(".eh_frame:     {:#010x}", section.address());
        bases = bases.set_eh_frame(section.address());
    }

    if let Some(section) = file.section_by_name(".text") {
        println!(".text:         {:#010x}", section.address());
        bases = bases.set_text(section.address());
    }

    if let Some(section) = file.section_by_name(".got") {
        println!(".got:          {:#010x}", section.address());
        bases = bases.set_text(section.address());
    }

    let mut entries = eh_frame.entries(&bases);

    let mut cies = HashMap::new();
    let mut ctx = Box::new(gimli::UnwindContext::new());

    while let Some(entry) = entries.next().context("failed to read .eh_frame entry")? {
        let fde = match entry {
            gimli::CieOrFde::Cie(_) => continue,
            gimli::CieOrFde::Fde(partial) => partial
                .parse(|_section, bases, offset| {
                    cies.entry(offset)
                        .or_insert_with(|| eh_frame.cie_from_offset(bases, offset))
                        .clone()
                })
                .context("failed to parse the frame descriptor entry")?,
        };

        let start_address = fde.initial_address();
        let len = fde.len();

        if start_address > i32::MAX as u64 {
            anyhow::bail!(
                "DWARF FDE at {} has an initial address {:x?} greater than 0x10000000 which \
                 cannot be represented in the SFrame format",
                fde.offset(),
                start_address,
            )
        }

        if len > i32::MAX as u64 {
            anyhow::bail!(
                "DWARF FDE at {} has function length {:x?} greater than 0x10000000 which cannot \
                 be represented in the SFrame format",
                fde.offset(),
                len,
            )
        }

        let mut sframe_fde =
            FuncDescBuilder::new(sframe.options(), start_address as i32, len as u32);
        let mut rows = fde
            .rows(&eh_frame, &bases, &mut ctx)
            .context("failed to read the rows of a FDE")?;

        println!("FDE:");
        println!(" start_address: {:#010x}", fde.initial_address());
        println!(
            "    range_size: {:#010x} (end_addr = {:#010x})",
            fde.len(),
            fde.initial_address() + fde.len()
        );

        let register_name = &|register| match gimli::X86_64::register_name(register) {
            Some(name) => Cow::Borrowed(name),
            None => Cow::Owned(format!("{}", register.0)),
        };

        dump_cfi_instructions(
            &mut std::io::stdout(),
            fde.instructions(&eh_frame, &bases),
            false,
            &register_name,
            fde.cie().encoding(),
        )?;
        println!();
        println!("Rows:");

        while let Some(row) = rows
            .next_row()
            .context("failed to evaluate FDE unwind table row")?
        {
            let start_address = match u32::try_from(row.start_address() - fde.initial_address()) {
                Ok(start_address) if start_address < i32::MAX as u32 => start_address,
                _ => {
                    anyhow::bail!(
                        "DWARF FDE unwind table row start address offset is greater than \
                         0x10000000 and cannot be represented in the SFrame format"
                    );
                }
            };

            println!(
                "  - offset: {:#010x} (end = {:#010x})",
                row.start_address(),
                row.end_address()
            );
            println!(
                "    cfa:    {}",
                match row.cfa() {
                    &gimli::CfaRule::RegisterAndOffset { register, offset } => format!(
                        "{}{}{}",
                        register_name(register),
                        if offset >= 0 { "+" } else { "-" },
                        offset.unsigned_abs()
                    ),
                    gimli::CfaRule::Expression(expr) => {
                        let mut output = String::new();
                        crate::fmthelp::dump_expression(
                            &mut output,
                            "            ",
                            fde.cie().encoding(),
                            expr.clone(),
                            register_name,
                        )
                        .unwrap();

                        output.trim().to_string()
                    }
                }
            );

            for (reg, rule) in row.registers() {
                let name = register_name(*reg);
                println!(
                    "    reg:    {name} = {}",
                    &RegisterRule::new(rule, file.architecture(), fde.cie().encoding())
                );
            }

            let result: anyhow::Result<()> = (|| {
                let (base, offset) = match row.cfa() {
                    gimli::CfaRule::RegisterAndOffset { register, offset } => match *register {
                        gimli::X86_64::RBP => (FreBaseRegId::Fp, offset),
                        gimli::X86_64::RSP => (FreBaseRegId::Sp, offset),
                        _ => anyhow::bail!(
                            "unsupported CFA source register {}",
                            register_name(*register)
                        ),
                    },
                    gimli::CfaRule::Expression(expr) => {
                        let eval = expr.evaluation(fde.cie().encoding());

                        anyhow::bail!(
                            "DWARF FDE unwind table row requires evaluating a DWARF expression: \
                             {eval:?}"
                        )
                    }
                };

                let offset = match i32::try_from(*offset) {
                    Ok(offset) => offset,
                    Err(_) => anyhow::bail!(
                        "DWARF FDE register recovery offset {offset:x} was outside the bounds of \
                         an i32"
                    ),
                };

                // TODO: Should this be relative to the frame pointer or the stack pointer?
                //
                // SFrame requires that we pick one, but there's no good way to know which one
                // to pick.

                // DWARF v5 (6.4) defines the CFA to be the stack pointer of the previous frame.
                let fp_offset = match row.register(gimli::X86_64::RBP) {
                    gimli::RegisterRule::Offset(offset) => {
                        let offset = i32::try_from(offset).with_context(|| {
                            format!(
                                "DWARF register offset {offset} was outside the bounds of an
                                 i32"
                            )
                        })?;

                        Some(offset)
                    }
                    gimli::RegisterRule::Undefined => None,
                    rule => {
                        eprintln!(
                            "unsupported recovery rule for RBP: {}",
                            RegisterRule::new(&rule, file.architecture(), fde.cie().encoding())
                        );
                        None
                    } // rule => anyhow::bail!("Unsupported recovery rule for RSP: {rule:?}"),
                };

                let ra_offset = match row.register(gimli::X86_64::RA) {
                    gimli::RegisterRule::Offset(offset) => {
                        let offset = i32::try_from(offset).with_context(|| {
                            format!(
                                "DWARF register offset {offset} was outside the bounds of an i32"
                            )
                        })?;

                        offset
                    }
                    rule => anyhow::bail!(
                        "Unsupported recovery rule for RA: {}",
                        RegisterRule::new(&rule, file.architecture(), fde.cie().encoding())
                    ),
                };

                let offsets = FrameRowOffsets {
                    cfa: offset,
                    fp: fp_offset,
                    ra: Some(ra_offset),
                };

                println!("    sframe: {offsets:?}");

                sframe_fde
                    .row(FrameRowBuilder::new(base, start_address, offsets))
                    .context("failed to build a row for the FDE")?;

                Ok(())
            })();

            if let Err(e) = result {
                eprintln!("{e:?}");

                // sframe_fde
                //     .row(
                //         FrameRowBuilder::new(
                //             FreBaseRegId::Fp,
                //             start_address,
                //             FrameRowOffsets {
                //                 cfa: 0,
                //                 ra: None,
                //                 fp: None,
                //             },
                //         )
                //         .mangled_ra_p(true),
                //     )
                //     .context("Failed to build an invalid row for the FDE")?;

                sframe_fde
                    .row(FrameRowBuilder::invalid(start_address))
                    .context("Failed to build an invalid row for the FDE")?;
            }
        }

        sframe_fde.merge_adjacent_fres();
        sframe.fde(sframe_fde);

        println!();
    }

    sframe.merge_adjacent_fdes();
    let bytes = sframe
        .build::<NativeEndian>()
        .context("failed to build the sframe section")?;

    // let section = elf_sframe::SFrame::<NativeEndian>::load(&bytes)
    //     .context("emitted sframe section was not valid")?;

    // println!("{section:#x?}");

    let mut outobj = object::write::Object::new(
        object::BinaryFormat::Elf,
        file.architecture(),
        file.endianness(),
    );

    let section = outobj.add_section(
        outobj
            .segment_name(object::write::StandardSegment::Debug)
            .to_vec(),
        b".sframe".to_vec(),
        object::SectionKind::Debug,
    );
    outobj.set_section_data(section, &bytes, 8);

    let mut data = Vec::new();
    outobj
        .emit(&mut data)
        .context("failed to emit the sframe object")?;

    std::fs::write(&args.output, &data)
        .with_context(|| format!("failed to write to `{}`", args.output.display()))?;

    Ok(())
}
