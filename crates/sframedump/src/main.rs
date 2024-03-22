use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::Context;
use elf_sframe::raw::v2::FreBaseRegId;
use elf_sframe::{FdeType, SFrame};
use object::{Object, ObjectSection};

const HELP: &str = "\
Dump SFrame debug information of an ELF object.

USAGE
    sframedump [OPTIONS] <object file>

DESCRIPTION
    sframedump prints the information contained in the .sframe section of an
    ELF object in a human readable format.

FLAGS
    -h
    --help
        Print this help message and then exit.
";

fn main() -> anyhow::Result<()> {
    let mut opts = getopts::Options::new();
    opts.optflag("h", "help", "show this help text");

    let matches = opts.parse(std::env::args().skip(1))?;

    if matches.opt_present("help") {
        eprintln!("{HELP}");
        return Ok(());
    }

    if matches.free.is_empty() {
        anyhow::bail!("no object file input provided");
    }

    if matches.free.len() != 1 {
        anyhow::bail!("at most one object file can be provided as an input")
    }

    let path = Path::new(&matches.free[0]);
    let file = File::open(&path).with_context(|| format!("failed to open `{}`", path.display()))?;
    let data = unsafe { memmap2::Mmap::map(&file) }
        .with_context(|| format!("failed to mmap `{}`", path.display()))?;
    let file = object::File::parse(&*data)
        .with_context(|| format!("failed to parse `{}`", path.display()))?;

    let section = match file.section_by_name(".sframe") {
        Some(section) => section,
        None => anyhow::bail!("elf binary has no .sframe section"),
    };

    let data = section
        .uncompressed_data()
        .context("failed to decompress the .eh_frame section")?;

    let sframe: SFrame = SFrame::load(&data).context("failed to decode .sframe section")?;
    let stdout = std::io::stdout();
    let mut w = BufWriter::new(stdout.lock());

    dump(&mut w, &sframe)
}

fn dump<W: Write>(w: &mut W, sframe: &SFrame) -> anyhow::Result<()> {
    writeln!(w, "Header:")?;
    writeln!(w, "  Version:  {}", sframe.version().0)?;
    writeln!(w, "  Flags:    {:#x}", sframe.flags().bits())?;
    writeln!(w, "  Num FDEs: {}", sframe.num_fdes())?;
    writeln!(w, "  Num FREs: {}", sframe.num_fres())?;
    writeln!(w, "  Arch/ABI: {:?}", sframe.abi())?;
    writeln!(
        w,
        "  Fixed FP Offset: {}",
        sframe
            .fixed_fp_offset()
            .map(|x| x.to_string())
            .unwrap_or_else(|| "none".to_string())
    )?;
    writeln!(
        w,
        "  Fixed RA Offset: {}",
        sframe
            .fixed_ra_offset()
            .map(|x| x.to_string())
            .unwrap_or_else(|| "none".to_string())
    )?;
    writeln!(w)?;
    writeln!(w, "Function Index:")?;

    for (idx, fde) in sframe.fdes().enumerate() {
        writeln!(
            w,
            "  func idx [{idx}]: pc = {:#x}, size = {} bytes",
            fde.start_address(),
            fde.size()
        )?;

        let marker = match fde.fdetype() {
            FdeType::PcInc => "   ",
            FdeType::PcMask => "[m]",
            FdeType::PcMaskV1 => "[1]",
        };

        writeln!(w, "  STARTPC {marker}      CFA          FP           RA")?;

        for fre in fde.fres() {
            let fre = match fre {
                Ok(fre) => fre,
                Err(e) => {
                    w.flush()?;
                    eprintln!("  error decoding FRE: {e}");
                    break;
                }
            };

            let base = match fre.cfa_base_reg_id() {
                FreBaseRegId::Fp => "fp",
                FreBaseRegId::Sp => "sp",
            };

            let cfa = match fre.cfa_offset() {
                Ok(offset) => format!("{base}{offset:+}"),
                Err(_) => "u".to_string(),
            };

            let fp = match fre.fp_offset(&sframe) {
                Ok(offset) => format!("cfa{offset:+}"),
                Err(_) => "u".to_string(),
            };

            let ra = match fre.ra_offset(&sframe) {
                Ok(offset) => format!("cfa{offset:+}"),
                Err(_) => "u".to_string(),
            };

            let mangled = match fre.mangled_ra_p() {
                true => " [s]",
                false => "",
            };

            writeln!(
                w,
                "  {:016x} {cfa: <12} {fp: <12} {ra:}{mangled}",
                fre.start_address()
            )?;
        }

        writeln!(w)?;
    }

    Ok(())
}
