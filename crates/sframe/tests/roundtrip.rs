use anyhow::Context;
use elf_sframe::raw::v2::FreBaseRegId;
use elf_sframe::write::FrameRowOffsets;
use elf_sframe::*;

#[test]
fn roundtrip() -> anyhow::Result<()> {
    let options = write::SFrameOptions::new();
    let mut sframe = write::SFrameBuilder::new(options);
    let mut fde = write::FuncDescBuilder::new(options, 0x1000, 0x100);

    fde.row(write::FrameRowBuilder::new(
        FreBaseRegId::Sp,
        0x00,
        FrameRowOffsets {
            cfa: -8,
            ra: Some(32),
            fp: Some(24),
        },
    ))?;
    fde.row(write::FrameRowBuilder::new(
        FreBaseRegId::Fp,
        0x10,
        FrameRowOffsets {
            cfa: 32,
            ra: None,
            fp: None,
        },
    ))?;
    fde.row(write::FrameRowBuilder::new(
        FreBaseRegId::Sp,
        0x20,
        FrameRowOffsets {
            cfa: 64,
            ra: Some(17),
            fp: None,
        },
    ))?;

    sframe.fde(fde);
    let data = sframe.build::<NativeEndian>()?;

    let sframe = SFrame::<NativeEndian>::load(&data).context("failed to load sframe section")?;

    assert_eq!(sframe.num_fdes(), 1);
    assert_eq!(sframe.num_fres(), 3);

    let mut fdes = sframe.fdes();
    let fde = fdes.next().unwrap();

    assert_eq!(fde.fdetype(), FdeType::PcInc);
    assert_eq!(fde.start_address(), 0x1000);

    let mut fres = fde.fres();
    let fre = fres.next().unwrap()?;

    assert_eq!(fre.cfa_base_reg_id(), FreBaseRegId::Sp);
    assert_eq!(fre.cfa_offset()?, -8);
    assert_eq!(fre.fp_offset(&sframe)?, 24);
    assert_eq!(fre.ra_offset(&sframe)?, 32);
    assert_eq!(fre.start_address_offset(), 0x0000);

    Ok(())
}

#[test]
fn roundtrip_u16_offset() -> anyhow::Result<()> {
    let options = write::SFrameOptions::new();
    let mut sframe = write::SFrameBuilder::new(options);
    let mut fde = write::FuncDescBuilder::new(options, 0x1000, 0x100000);

    fde.row(write::FrameRowBuilder::new(
        FreBaseRegId::Sp,
        0x100,
        FrameRowOffsets {
            cfa: -0x100,
            ra: Some(32),
            fp: Some(24),
        },
    ))?;

    sframe.fde(fde);
    let data = sframe.build::<NativeEndian>()?;

    let sframe = SFrame::<NativeEndian>::load(&data).context("failed to load sframe section")?;

    assert_eq!(sframe.num_fdes(), 1);
    assert_eq!(sframe.num_fres(), 1);

    let mut fdes = sframe.fdes();
    let fde = fdes.next().unwrap();

    assert_eq!(fde.fdetype(), FdeType::PcInc);
    assert_eq!(fde.start_address(), 0x1000);

    let mut fres = fde.fres();
    let fre = fres.next().unwrap()?;

    assert_eq!(fre.cfa_base_reg_id(), FreBaseRegId::Sp);
    assert_eq!(fre.cfa_offset()?, -0x100);
    assert_eq!(fre.fp_offset(&sframe)?, 24);
    assert_eq!(fre.ra_offset(&sframe)?, 32);
    assert_eq!(fre.start_address_offset(), 0x100);

    Ok(())
}

#[test]
fn roundtrip_invalid_fre() -> anyhow::Result<()> {
    let options = write::SFrameOptions::new();
    let mut sframe = write::SFrameBuilder::new(options);
    let mut fde = write::FuncDescBuilder::new(options, 0x1000, 0x100000);

    fde.row(write::FrameRowBuilder::invalid(0x10))?;

    sframe.fde(fde);
    let data = sframe.build::<NativeEndian>()?;

    let sframe = SFrame::<NativeEndian>::load(&data).context("failed to load sframe section")?;

    let mut fdes = sframe.fdes();

    let fde = fdes.next().unwrap();
    assert_eq!(fde.fdetype(), FdeType::PcInc);
    assert_eq!(fde.start_address(), 0x1000);

    let mut fres = fde.fres();

    let fre = fres.next().unwrap()?;
    assert!(fre.cfa_offset().is_err());
    assert!(fre.fp_offset(&sframe).is_err());
    assert!(fre.ra_offset(&sframe).is_err());

    Ok(())
}
