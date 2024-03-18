//!

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod error;
pub mod raw;
pub mod read;
pub mod write;

pub use self::error::ReadError;
