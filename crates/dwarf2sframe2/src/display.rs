//! Display helpers for use when emitting warnings.

use std::fmt;

use crate::Architecture;

pub(crate) struct DisplayRegister {
    arch: Architecture,
    reg: gimli::Register,
}

impl DisplayRegister {
    pub fn new(arch: Architecture, reg: gimli::Register) -> Self {
        Self { arch, reg }
    }
}

impl fmt::Display for DisplayRegister {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self.arch {
            Architecture::Amd64 => gimli::X86_64::register_name(self.reg),
            Architecture::Aarch64 => gimli::AArch64::register_name(self.reg),
        };

        match name {
            Some(name) => f.write_str(name),
            None => self.reg.0.fmt(f),
        }
    }
}

pub struct RegisterRule<'a, R: gimli::Reader> {
    pub rule: &'a gimli::RegisterRule<R>,
    pub arch: Architecture,
}

impl<'a, R: gimli::Reader> RegisterRule<'a, R> {
    pub fn new(rule: &'a gimli::RegisterRule<R>, arch: Architecture) -> Self {
        Self { rule, arch }
    }
}

impl<'a, R: gimli::Reader> fmt::Display for RegisterRule<'a, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use gimli::RegisterRule::*;

        match self.rule {
            Undefined => write!(f, "<undefined>"),
            SameValue => write!(f, "<same>"),
            Offset(offset) => write!(f, "*(CFA{offset:+})"),
            ValOffset(offset) => write!(f, "CFA{offset:+}"),
            Register(reg) => DisplayRegister::new(self.arch, *reg).fmt(f),
            Constant(value) => write!(f, "{value}"),
            rule => write!(f, "{rule:?}"),
        }
    }
}
