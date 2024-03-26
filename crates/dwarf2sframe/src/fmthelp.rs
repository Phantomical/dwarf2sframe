use std::borrow::Cow;
use std::fmt;

use gimli::Reader;
use object::Architecture;

pub struct RegisterRule<'a, R: Reader<Offset = usize>> {
    pub rule: &'a gimli::RegisterRule<R>,
    pub arch: Architecture,
    pub encoding: gimli::Encoding,
}

impl<'a, R: Reader<Offset = usize>> RegisterRule<'a, R> {
    pub fn new(
        rule: &'a gimli::RegisterRule<R>,
        arch: Architecture,
        encoding: gimli::Encoding,
    ) -> Self {
        Self {
            rule,
            arch,
            encoding,
        }
    }

    fn regname(&self, reg: gimli::Register) -> Cow<'static, str> {
        let name = match self.arch {
            Architecture::X86_64 => gimli::X86_64::register_name(reg),
            Architecture::X86_64_X32 => gimli::X86::register_name(reg),
            Architecture::Aarch64 => gimli::AArch64::register_name(reg),
            Architecture::Arm => gimli::Arm::register_name(reg),
            Architecture::Riscv32 | Architecture::Riscv64 => gimli::RiscV::register_name(reg),
            Architecture::LoongArch64 => gimli::LoongArch::register_name(reg),
            _ => None,
        };

        match name {
            Some(name) => Cow::Borrowed(name),
            None => Cow::Owned(reg.0.to_string()),
        }
    }
}

impl<'a, R: Reader<Offset = usize>> fmt::Display for RegisterRule<'a, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use gimli::RegisterRule::*;

        match self.rule {
            Undefined => write!(f, "<undefined>"),
            SameValue => write!(f, "<same>"),
            Offset(offset) => write!(f, "*(CFA{offset:+})"),
            ValOffset(offset) => write!(f, "CFA{offset:+}"),
            Register(reg) => write!(f, "{}", self.regname(*reg)),
            Constant(value) => write!(f, "{value}"),
            Expression(expr) => {
                let mut output = String::new();
                dump_expression(
                    &mut output,
                    "        ",
                    self.encoding,
                    expr.clone(),
                    &|reg| self.regname(reg),
                )?;

                f.write_str(output.trim())
            }
            rule => write!(f, "{rule:?}"),
        }
    }
}

pub(crate) fn dump_expression<R: gimli::Reader<Offset = usize>, W: fmt::Write>(
    w: &mut W,
    indent: &str,
    encoding: gimli::Encoding,
    expr: gimli::Expression<R>,
    register_name: &dyn Fn(gimli::Register) -> Cow<'static, str>,
) -> fmt::Result {
    use gimli::Operation::*;

    let i = indent;
    let mut opiter = expr.operations(encoding);

    while let Some(op) = opiter.next().map_err(|_| fmt::Error)? {
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
