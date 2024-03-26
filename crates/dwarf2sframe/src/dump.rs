use std::borrow::Cow;
use std::io::Write;

#[allow(clippy::unneeded_field_pattern)]
pub(crate) fn dump_cfi_instructions<R: gimli::Reader<Offset = usize>, W: Write>(
    w: &mut W,
    mut insns: gimli::CallFrameInstructionIter<R>,
    is_initial: bool,
    register_name: &dyn Fn(gimli::Register) -> Cow<'static, str>,
    encoding: gimli::Encoding,
) -> gimli::Result<()> {
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

pub(crate) fn dump_expression<R: gimli::Reader<Offset = usize>, W: Write>(
    w: &mut W,
    indent: &str,
    encoding: gimli::Encoding,
    expr: gimli::Expression<R>,
    register_name: &dyn Fn(gimli::Register) -> Cow<'static, str>,
) -> gimli::Result<()> {
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
