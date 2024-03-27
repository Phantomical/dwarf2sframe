use std::fs::File;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use elf_sframe::{BigEndian, LittleEndian};
use gimli::RunTimeEndian;
use object::{Endianness, Object, ObjectSection};

#[derive(Debug, Parser)]
struct Args {
    input: PathBuf,

    /// Output file.
    #[arg(long, short)]
    output: PathBuf,

    /// Create a dump of the dwarf unwind info as it is processed.
    #[arg(long)]
    debug_dump: bool,

    #[arg(long)]
    warnings: bool,

    /// Disable optimizations applied to the generated SFrame section.
    #[arg(long)]
    no_opt: bool,
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
    let arch = match file.architecture() {
        object::Architecture::X86_64 => dwarf2sframe2::Architecture::Amd64,
        object::Architecture::Aarch64 => dwarf2sframe2::Architecture::Aarch64,
        arch => anyhow::bail!("Unsupported architecture: {arch:?}"),
    };

    let section = match file.section_by_name(".eh_frame") {
        Some(section) => section,
        None => anyhow::bail!("elf binary has no .eh_frame section"),
    };
    let data = section
        .uncompressed_data()
        .context("failed to decompress the .eh_frame section")?;

    let eh_frame = gimli::EhFrame::new(&data, endian);

    let mut bases = gimli::BaseAddresses::default();
    if let Some(section) = file.section_by_name(".eh_frame_hdr") {
        bases = bases.set_eh_frame_hdr(section.address());
    }

    if let Some(section) = file.section_by_name(".eh_frame") {
        bases = bases.set_eh_frame(section.address());
    }

    if let Some(section) = file.section_by_name(".text") {
        bases = bases.set_text(section.address());
    }

    if let Some(section) = file.section_by_name(".got") {
        bases = bases.set_text(section.address());
    }

    let options = dwarf2sframe2::Options::new(arch, bases)
        .debugdump(args.debug_dump)
        .merge_fdes(!args.no_opt)
        .merge_fres(!args.no_opt)
        .endian(endian)
        .warnings(args.warnings);
    let sframe = dwarf2sframe2::dwarf2sframe(eh_frame, &options)?;

    let bytes = match endian {
        RunTimeEndian::Big => sframe.build::<BigEndian>(),
        RunTimeEndian::Little => sframe.build::<LittleEndian>(),
    };
    let bytes = bytes.context("failed to build the sframe section")?;

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
