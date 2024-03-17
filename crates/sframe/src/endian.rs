use self::private::Sealed;

mod private {
    pub trait Sealed {}
}

pub trait Endian: Sealed {
    fn u8_from_bytes(&self, bytes: [u8; 1]) -> u8;
    fn u16_from_bytes(&self, bytes: [u8; 2]) -> u16;
    fn u32_from_bytes(&self, bytes: [u8; 4]) -> u32;
    fn u64_from_bytes(&self, bytes: [u8; 8]) -> u64;

    fn i8_from_bytes(&self, bytes: [u8; 1]) -> u8 {
        self.u8_from_bytes(bytes) as _
    }
    fn i16_from_bytes(&self, bytes: [u8; 2]) -> u16 {
        self.u16_from_bytes(bytes) as _
    }
    fn i32_from_bytes(&self, bytes: [u8; 4]) -> u32 {
        self.u32_from_bytes(bytes) as _
    }
    fn i64_from_bytes(&self, bytes: [u8; 8]) -> u64 {
        self.u64_from_bytes(bytes) as _
    }

    fn u8_to_bytes(&self, value: u8) -> [u8; 1];
    fn u16_to_bytes(&self, value: u16) -> [u8; 2];
    fn u32_to_bytes(&self, value: u32) -> [u8; 4];
    fn u64_to_bytes(&self, value: u64) -> [u8; 8];

    fn i8_to_bytes(&self, value: i8) -> [u8; 1] {
        self.u8_to_bytes(value as _)
    }
    fn i16_to_bytes(&self, value: i16) -> [u8; 2] {
        self.u16_to_bytes(value as _)
    }
    fn i32_to_bytes(&self, value: i32) -> [u8; 4] {
        self.u32_to_bytes(value as _)
    }
    fn i64_to_bytes(&self, value: i64) -> [u8; 8] {
        self.u64_to_bytes(value as _)
    }
}

macro_rules! endian_impl {
    ($type:ty => $from:ident $to:ident) => {
        impl Endian for $type {
            fn u8_from_bytes(&self, bytes: [u8; 1]) -> u8 {
                u8::$from(bytes)
            }
            fn u16_from_bytes(&self, bytes: [u8; 2]) -> u16 {
                u16::$from(bytes)
            }
            fn u32_from_bytes(&self, bytes: [u8; 4]) -> u32 {
                u32::$from(bytes)
            }
            fn u64_from_bytes(&self, bytes: [u8; 8]) -> u64 {
                u64::$from(bytes)
            }
            
            fn u8_to_bytes(&self, value: u8) -> [u8; 1] {
                value.$to()
            }
            fn u16_to_bytes(&self, value: u16) -> [u8; 2] {
                value.$to()
            }
            fn u32_to_bytes(&self, value: u32) -> [u8; 4] {
                value.$to()
            }
            fn u64_to_bytes(&self, value: u64) -> [u8; 8] {
                value.$to()
            }
        }

        impl Sealed for $type {}
    };
}

#[derive(Copy, Clone, Debug)]
pub struct Native;

#[derive(Copy, Clone, Debug)]
pub struct Little;

#[derive(Copy, Clone, Debug)]
pub struct Big;

endian_impl!(Native => from_ne_bytes to_be_bytes);
endian_impl!(Little => from_le_bytes to_le_bytes);
endian_impl!(Big => from_be_bytes to_be_bytes);
