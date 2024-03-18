use std::path::PathBuf;

use elf_sframe::{NativeEndian, SFrame};

fn main() {
    let path = std::env::args_os()
        .next()
        .expect("USAGE: debug-dump <sframe file>");
    let path = PathBuf::from(path);

    let data = std::fs::read(&path).expect("could not read sframe file");
    let sframe = SFrame::<NativeEndian>::load(&data).expect("failed to parse sframe file");

    println!("{sframe:?}");
}
