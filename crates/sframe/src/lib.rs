//! `elf-sframe` is a library for reading and writing the
//! [SFrame debugging format][0].
//!
//! The Simple Frame (SFrame) format keeps track of the minimal necessary
//! information needed to generate a stack trace:
//! - the Canonical Frame Pointer (CFA),
//! - the Frame Pointer (FP), and,
//! - the Return Address (RA).
//!
//! Its goal is to provide a simple, fast, and low-overhead mechanism to
//! generate stack traces.
//!
//! [0]: https://sourceware.org/binutils/docs-2.41/sframe-spec.html
//!
//! # Modules
//! - Types to read a SFrame format are available in the crate root.
//! - [`raw`] - Raw SFrame types as they are defined in the specification.
//! - [`write`][mod@write] - Generate and write out a new sframe section.

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod error;
pub mod raw;
mod read;
pub mod write;

pub use zerocopy::{BigEndian, LittleEndian, NativeEndian, ByteOrder};

pub use self::error::ReadError;
pub use self::read::*;
