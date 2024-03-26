// Allow clippy lints when building without clippy.
#![allow(unknown_lints)]

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::{io, mem, result};

use anyhow::Context;
use gimli::{Section, UnwindSection};
use object::{Object, ObjectSection};
use typed_arena::Arena;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    GimliError(gimli::Error),
    ObjectError(object::read::Error),
    IoError,
}

impl fmt::Display for Error {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> ::std::result::Result<(), fmt::Error> {
        Debug::fmt(self, f)
    }
}

impl From<gimli::Error> for Error {
    fn from(err: gimli::Error) -> Self {
        Error::GimliError(err)
    }
}

impl From<io::Error> for Error {
    fn from(_: io::Error) -> Self {
        Error::IoError
    }
}

impl From<object::read::Error> for Error {
    fn from(err: object::read::Error) -> Self {
        Error::ObjectError(err)
    }
}

pub type Result<T> = result::Result<T, Error>;

trait Reader: gimli::Reader<Offset = usize> + Send + Sync {}

impl<'input, Endian> Reader for gimli::EndianSlice<'input, Endian> where
    Endian: gimli::Endianity + Send + Sync
{
}

fn main() -> anyhow::Result<()> {
    let path = std::env::args_os()
        .skip(1)
        .next()
        .expect("USAGE: dwarf2sframe <elf file>");
    let path = PathBuf::from(path);
    let file = File::open(&path).with_context(|| format!("failed to open `{}`", path.display()))?;
    let file = unsafe { memmap2::Mmap::map(&file) }
        .with_context(|| format!("failed to mmap `{}`", path.display()))?;
    let file = object::File::parse(&*file)
        .with_context(|| format!("failed to parse `{}`", path.display()))?;

    let endian = if file.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };
    match dump_file(&file, endian) {
        Ok(_) => (),
        Err(err) => eprintln!("Failed to dump '{}': {}", path.display(), err,),
    }

    Ok(())
}

fn load_file_section<'input, 'arena, Endian: gimli::Endianity>(
    id: gimli::SectionId,
    file: &object::File<'input>,
    endian: Endian,
    arena_data: &'arena Arena<Cow<'input, [u8]>>,
) -> Result<gimli::EndianSlice<'arena, Endian>> {
    let data = match file.section_by_name(id.name()) {
        Some(ref section) => {
            // DWO sections never have relocations, so don't bother.
            section.uncompressed_data()?
        }
        // Use a non-zero capacity so that `ReaderOffsetId`s are unique.
        None => Cow::Owned(Vec::with_capacity(1)),
    };
    let data_ref = arena_data.alloc(data);
    let reader = gimli::EndianSlice::new(data_ref, endian);
    Ok(reader)
}

fn dump_file<Endian>(file: &object::File, endian: Endian) -> Result<()>
where
    Endian: gimli::Endianity + Send + Sync,
{
    let arena_data = Arena::new();

    let load_section =
        |id: gimli::SectionId| -> Result<_> { load_file_section(id, file, endian, &arena_data) };

    let w = &mut BufWriter::new(io::stdout());
    let eh_frame = gimli::EhFrame::load(load_section).unwrap();
    dump_eh_frame(w, file, eh_frame)?;
    w.flush()?;
    Ok(())
}

fn dump_eh_frame<R: Reader, W: Write>(
    w: &mut W,
    file: &object::File,
    mut eh_frame: gimli::EhFrame<R>,
) -> Result<()> {
    // TODO: this might be better based on the file format.
    let address_size = file
        .architecture()
        .address_size()
        .map(|w| w.bytes())
        .unwrap_or(mem::size_of::<usize>() as u8);
    eh_frame.set_address_size(address_size);

    // There are other things we could match but currently don't
    #[allow(clippy::single_match)]
    match file.architecture() {
        object::Architecture::Aarch64 => eh_frame.set_vendor(gimli::Vendor::AArch64),
        _ => {}
    }

    fn register_name_none(_: gimli::Register) -> Option<&'static str> {
        None
    }
    let arch_register_name = match file.architecture() {
        object::Architecture::Arm | object::Architecture::Aarch64 => gimli::Arm::register_name,
        object::Architecture::I386 => gimli::X86::register_name,
        object::Architecture::X86_64 => gimli::X86_64::register_name,
        _ => register_name_none,
    };
    let register_name = &|register| match arch_register_name(register) {
        Some(name) => Cow::Borrowed(name),
        None => Cow::Owned(format!("{}", register.0)),
    };

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
        bases = bases.set_got(section.address());
    }

    // TODO: Print "__eh_frame" here on macOS, and more generally use the
    // section that we're actually looking at, which is what the canonical
    // dwarfdump does.
    writeln!(
        w,
        "Exception handling frame information for section .eh_frame"
    )?;

    let mut cies = HashMap::new();

    let mut entries = eh_frame.entries(&bases);
    loop {
        match entries.next()? {
            None => return Ok(()),
            Some(gimli::CieOrFde::Cie(cie)) => {
                writeln!(w)?;
                writeln!(w, "{:#010x}: CIE", cie.offset())?;
                writeln!(w, "        length: {:#010x}", cie.entry_len())?;
                // TODO: CIE_id
                writeln!(w, "       version: {:#04x}", cie.version())?;
                // TODO: augmentation
                writeln!(w, "    code_align: {}", cie.code_alignment_factor())?;
                writeln!(w, "    data_align: {}", cie.data_alignment_factor())?;
                writeln!(
                    w,
                    "   ra_register: {}",
                    register_name(cie.return_address_register())
                )?;
                if let Some(encoding) = cie.lsda_encoding() {
                    writeln!(
                        w,
                        " lsda_encoding: {}/{}",
                        encoding.application(),
                        encoding.format()
                    )?;
                }
                if let Some((encoding, personality)) = cie.personality_with_encoding() {
                    write!(
                        w,
                        "   personality: {}/{} ",
                        encoding.application(),
                        encoding.format()
                    )?;
                    dump_pointer(w, personality)?;
                    writeln!(w)?;
                }
                if let Some(encoding) = cie.fde_address_encoding() {
                    writeln!(
                        w,
                        "  fde_encoding: {}/{}",
                        encoding.application(),
                        encoding.format()
                    )?;
                }
                let instructions = cie.instructions(&eh_frame, &bases);
                dump_cfi_instructions(w, instructions, true, register_name, cie.encoding())?;
                writeln!(w)?;
            }
            Some(gimli::CieOrFde::Fde(partial)) => {
                writeln!(w)?;
                writeln!(w, "{:#010x}: FDE", partial.offset())?;
                writeln!(w, "        length: {:#010x}", partial.entry_len())?;
                writeln!(w, "   CIE_pointer: {:#010x}", partial.cie_offset().0)?;

                let fde = match partial.parse(|_, bases, o| {
                    cies.entry(o)
                        .or_insert_with(|| eh_frame.cie_from_offset(bases, o))
                        .clone()
                }) {
                    Ok(fde) => fde,
                    Err(e) => {
                        writeln!(w, "Failed to parse FDE: {}", e)?;
                        continue;
                    }
                };

                // TODO: symbolicate the start address like the canonical dwarfdump does.
                writeln!(w, "    start_addr: {:#018x}", fde.initial_address())?;
                writeln!(
                    w,
                    "    range_size: {:#018x} (end_addr = {:#018x})",
                    fde.len(),
                    fde.initial_address() + fde.len()
                )?;
                if let Some(lsda) = fde.lsda() {
                    write!(w, "          lsda: ")?;
                    dump_pointer(w, lsda)?;
                    writeln!(w)?;
                }
                let instructions = fde.instructions(&eh_frame, &bases);
                dump_cfi_instructions(w, instructions, false, register_name, fde.cie().encoding())?;
                writeln!(w)?;
            }
        }
    }
}

fn dump_pointer<W: Write>(w: &mut W, p: gimli::Pointer) -> Result<()> {
    match p {
        gimli::Pointer::Direct(p) => {
            write!(w, "{:#018x}", p)?;
        }
        gimli::Pointer::Indirect(p) => {
            write!(w, "({:#018x})", p)?;
        }
    }
    Ok(())
}

#[allow(clippy::unneeded_field_pattern)]
fn dump_cfi_instructions<R: Reader, W: Write>(
    w: &mut W,
    mut insns: gimli::CallFrameInstructionIter<R>,
    is_initial: bool,
    register_name: &dyn Fn(gimli::Register) -> Cow<'static, str>,
    encoding: gimli::Encoding,
) -> Result<()> {
    use gimli::CallFrameInstruction::*;

    // TODO: we need to actually evaluate these instructions as we iterate them
    // so we can print the initialized state for CIEs, and each unwind row's
    // registers for FDEs.
    //
    // TODO: We should print DWARF expressions for the CFI instructions that
    // embed DWARF expressions within themselves.

    if !is_initial {
        writeln!(w, "  Instructions:")?;
    }

    loop {
        match insns.next() {
            Err(e) => {
                writeln!(w, "Failed to decode CFI instruction: {}", e)?;
                return Ok(());
            }
            Ok(None) => {
                if is_initial {
                    writeln!(w, "  Instructions: Init State:")?;
                }
                return Ok(());
            }
            Ok(Some(op)) => match op {
                SetLoc { address } => {
                    writeln!(w, "                DW_CFA_set_loc ({:#x})", address)?;
                }
                AdvanceLoc { delta } => {
                    writeln!(w, "                DW_CFA_advance_loc ({})", delta)?;
                }
                DefCfa { register, offset } => {
                    writeln!(
                        w,
                        "                DW_CFA_def_cfa ({}, {})",
                        register_name(register),
                        offset
                    )?;
                }
                DefCfaSf {
                    register,
                    factored_offset,
                } => {
                    writeln!(
                        w,
                        "                DW_CFA_def_cfa_sf ({}, {})",
                        register_name(register),
                        factored_offset
                    )?;
                }
                DefCfaRegister { register } => {
                    writeln!(
                        w,
                        "                DW_CFA_def_cfa_register ({})",
                        register_name(register)
                    )?;
                }
                DefCfaOffset { offset } => {
                    writeln!(w, "                DW_CFA_def_cfa_offset ({})", offset)?;
                }
                DefCfaOffsetSf { factored_offset } => {
                    writeln!(
                        w,
                        "                DW_CFA_def_cfa_offset_sf ({})",
                        factored_offset
                    )?;
                }
                DefCfaExpression { expression } => {
                    writeln!(w, "                DW_CFA_def_cfa_expression (...)")?;

                    dump_expression(w, "                  ", encoding, expression, register_name)?;
                }
                Undefined { register } => {
                    writeln!(
                        w,
                        "                DW_CFA_undefined ({})",
                        register_name(register)
                    )?;
                }
                SameValue { register } => {
                    writeln!(
                        w,
                        "                DW_CFA_same_value ({})",
                        register_name(register)
                    )?;
                }
                Offset {
                    register,
                    factored_offset,
                } => {
                    writeln!(
                        w,
                        "                DW_CFA_offset ({}, {})",
                        register_name(register),
                        factored_offset
                    )?;
                }
                OffsetExtendedSf {
                    register,
                    factored_offset,
                } => {
                    writeln!(
                        w,
                        "                DW_CFA_offset_extended_sf ({}, {})",
                        register_name(register),
                        factored_offset
                    )?;
                }
                ValOffset {
                    register,
                    factored_offset,
                } => {
                    writeln!(
                        w,
                        "                DW_CFA_val_offset ({}, {})",
                        register_name(register),
                        factored_offset
                    )?;
                }
                ValOffsetSf {
                    register,
                    factored_offset,
                } => {
                    writeln!(
                        w,
                        "                DW_CFA_val_offset_sf ({}, {})",
                        register_name(register),
                        factored_offset
                    )?;
                }
                Register {
                    dest_register,
                    src_register,
                } => {
                    writeln!(
                        w,
                        "                DW_CFA_register ({}, {})",
                        register_name(dest_register),
                        register_name(src_register)
                    )?;
                }
                Expression {
                    register,
                    expression,
                } => {
                    writeln!(
                        w,
                        "                DW_CFA_expression ({}, ...)",
                        register_name(register)
                    )?;

                    dump_expression(w, "                  ", encoding, expression, register_name)?;
                }
                ValExpression {
                    register,
                    expression,
                } => {
                    writeln!(
                        w,
                        "                DW_CFA_val_expression ({}, ...)",
                        register_name(register)
                    )?;

                    dump_expression(w, "                  ", encoding, expression, register_name)?;
                }
                Restore { register } => {
                    writeln!(
                        w,
                        "                DW_CFA_restore ({})",
                        register_name(register)
                    )?;
                }
                RememberState => {
                    writeln!(w, "                DW_CFA_remember_state")?;
                }
                RestoreState => {
                    writeln!(w, "                DW_CFA_restore_state")?;
                }
                ArgsSize { size } => {
                    writeln!(w, "                DW_CFA_GNU_args_size ({})", size)?;
                }
                NegateRaState => {
                    writeln!(w, "                DW_CFA_AARCH64_negate_ra_state")?;
                }
                Nop => {
                    writeln!(w, "                DW_CFA_nop")?;
                }
                _ => {
                    writeln!(w, "                {:?}", op)?;
                }
            },
        }
    }
}

fn dump_expression<R: Reader, W: Write>(
    w: &mut W,
    indent: &str,
    encoding: gimli::Encoding,
    expr: gimli::Expression<R>,
    register_name: &dyn Fn(gimli::Register) -> Cow<'static, str>,
) -> Result<()> {
    use gimli::Operation::*;

    let i = indent;
    let mut opiter = expr.operations(encoding);

    while let Some(op) = opiter.next()? {
        match op {
            Deref {
                base_type,
                size,
                space,
            } => writeln!(w, "{i}DW_OP_deref {} {size} {space}", base_type.0),
            Drop => writeln!(w, "{i}DW_OP_drop"),
            Pick { index } => writeln!(w, "{i}DW_OP_pick {index}"),
            Swap => writeln!(w, "{i}DW_OP_swap"),
            Rot => writeln!(w, "{i}DW_OP_rot"),
            Abs => writeln!(w, "{i}DW_OP_abs"),
            And => writeln!(w, "{i}DW_OP_and"),
            Div => writeln!(w, "{i}DW_OP_div"),
            Mul => writeln!(w, "{i}DW_OP_mul"),
            Neg => writeln!(w, "{i}DW_OP_neg"),
            Not => writeln!(w, "{i}DW_OP_not"),
            Plus => writeln!(w, "{i}DW_OP_plus"),
            PlusConstant { value } => writeln!(w, "{i}DW_OP_plusconstant {value}"),
            Shl => writeln!(w, "{i}DW_OP_shl"),
            Shr => writeln!(w, "{i}DW_OP_shr"),
            Xor => writeln!(w, "{i}DW_OP_xor"),
            Bra { target } => writeln!(w, "{i}DW_OP_bra {target}"),
            Eq => writeln!(w, "{i}DW_OP_eq"),
            Ge => writeln!(w, "{i}DW_OP_ge"),
            Lt => writeln!(w, "{i}DW_OP_lt"),
            Gt => writeln!(w, "{i}DW_OP_gt"),
            Le => writeln!(w, "{i}DW_OP_le"),
            Ne => writeln!(w, "{i}DW_OP_ne"),
            Skip { target } => writeln!(w, "{i}DW_OP_skip {target}"),
            UnsignedConstant { value } => writeln!(w, "{i}DW_OP_uconst {value}"),
            SignedConstant { value } => writeln!(w, "{i}DW_OP_sconst {value}"),
            Register { register } => writeln!(w, "{i}DW_OP_register {}", register_name(register)),
            RegisterOffset {
                register,
                offset,
                base_type,
            } => writeln!(
                w,
                "{i}DW_OP_register_offset {} {offset} {}",
                register_name(register),
                base_type.0
            ),
            FrameOffset { offset } => writeln!(w, "{i}DW_OP_frame_offset {offset}"),
            Nop => writeln!(w, "{i}DW_OP_nop"),
            PushObjectAddress => writeln!(w, "{i}DW_OP_push_object_address"),
            Call { offset } => writeln!(w, "{i}DW_OP_call {offset:?}"),
            TLS => writeln!(w, "{i}DW_OP_tls"),
            StackValue => writeln!(w, "{i}DW_OP_stack_value"),
            expr => writeln!(w, "{expr:?}"),
        }?
    }

    Ok(())
}
