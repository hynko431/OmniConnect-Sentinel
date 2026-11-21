use image::codecs::jpeg::JpegEncoder;
use image::{DynamicImage, GenericImageView, ImageBuffer, Rgb};
use sentinel_cdr::sanitizers::image::ImageSanitizer;
use sentinel_cdr::{CdrEngine, SanitizationPolicy, DEFAULT_JPEG_REENCODE_QUALITY};

/// Builds a valid minimal TIFF payload containing an IFD0 Orientation (`0x0112`) tag.
fn build_tiff_with_orientation(orientation: u16, big_endian: bool) -> Vec<u8> {
    let mut tiff = Vec::new();
    if big_endian {
        tiff.extend_from_slice(b"MM");
        tiff.extend_from_slice(&42u16.to_be_bytes());
        tiff.extend_from_slice(&8u32.to_be_bytes()); // IFD0 offset = 8
        tiff.extend_from_slice(&1u16.to_be_bytes()); // 1 IFD entry
        tiff.extend_from_slice(&0x0112u16.to_be_bytes()); // Tag: Orientation
        tiff.extend_from_slice(&3u16.to_be_bytes()); // Type: SHORT
        tiff.extend_from_slice(&1u32.to_be_bytes()); // Count: 1
        tiff.extend_from_slice(&orientation.to_be_bytes()); // Left-justified SHORT value
        tiff.extend_from_slice(&0u16.to_be_bytes()); // Padding
        tiff.extend_from_slice(&0u32.to_be_bytes()); // Next IFD = 0
    } else {
        tiff.extend_from_slice(b"II");
        tiff.extend_from_slice(&42u16.to_le_bytes());
        tiff.extend_from_slice(&8u32.to_le_bytes()); // IFD0 offset = 8
        tiff.extend_from_slice(&1u16.to_le_bytes()); // 1 IFD entry
        tiff.extend_from_slice(&0x0112u16.to_le_bytes()); // Tag: Orientation
        tiff.extend_from_slice(&3u16.to_le_bytes()); // Type: SHORT
        tiff.extend_from_slice(&1u32.to_le_bytes()); // Count: 1
        tiff.extend_from_slice(&orientation.to_le_bytes()); // Left-justified SHORT value
        tiff.extend_from_slice(&0u16.to_le_bytes()); // Padding
        tiff.extend_from_slice(&0u32.to_le_bytes()); // Next IFD = 0
    }
    tiff
}

/// Inserts a JPEG marker segment (`0xFF <marker> <len BE> <payload>`) immediately after SOI (`FF D8`).
fn inject_jpeg_segment(jpeg: &[u8], marker: u8, payload: &[u8]) -> Vec<u8> {
    assert!(jpeg.len() >= 2 && jpeg[0] == 0xFF && jpeg[1] == 0xD8);
    let seg_len = u16::try_from(payload.len() + 2).expect("segment length fits in u16");
    let mut out = Vec::with_capacity(jpeg.len() + payload.len() + 4);
    out.extend_from_slice(&jpeg[0..2]);
    out.push(0xFF);
    out.push(marker);
    out.extend_from_slice(&seg_len.to_be_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(&jpeg[2..]);
    out
}

/// Encodes an ICC 20-byte `XYZType` tag payload from floating-point D50 chromaticities.
fn encode_icc_xyz_tag(x: f64, y: f64, z: f64) -> [u8; 20] {
    let mut buf = [0u8; 20];
    buf[0..4].copy_from_slice(b"XYZ ");
    buf[8..12].copy_from_slice(&((x * 65_536.0).round() as i32).to_be_bytes());
    buf[12..16].copy_from_slice(&((y * 65_536.0).round() as i32).to_be_bytes());
    buf[16..20].copy_from_slice(&((z * 65_536.0).round() as i32).to_be_bytes());
    buf
}

/// Builds a structurally valid ICC v2 RGB/XYZ display profile with custom description and primaries.
fn build_icc_rgb_profile(
    desc_text: &str,
    r: (f64, f64, f64),
    g: (f64, f64, f64),
    b: (f64, f64, f64),
) -> Vec<u8> {
    let mut desc_payload = Vec::new();
    desc_payload.extend_from_slice(b"desc");
    desc_payload.extend_from_slice(&[0u8; 4]);
    desc_payload.extend_from_slice(&((desc_text.len() + 1) as u32).to_be_bytes());
    desc_payload.extend_from_slice(desc_text.as_bytes());
    desc_payload.push(0);
    while desc_payload.len() % 4 != 0 {
        desc_payload.push(0);
    }

    let r_tag = encode_icc_xyz_tag(r.0, r.1, r.2);
    let g_tag = encode_icc_xyz_tag(g.0, g.1, g.2);
    let b_tag = encode_icc_xyz_tag(b.0, b.1, b.2);

    let table_end = 132 + 4 * 12; // 4 tags: desc, rXYZ, gXYZ, bXYZ
    let desc_off = table_end;
    let r_off = desc_off + desc_payload.len();
    let g_off = r_off + 20;
    let b_off = g_off + 20;
    let total_len = b_off + 20;

    let mut icc = vec![0u8; total_len];
    icc[0..4].copy_from_slice(&(total_len as u32).to_be_bytes());
    icc[8] = 2; // ICC v2
    icc[12..16].copy_from_slice(b"mntr");
    icc[16..20].copy_from_slice(b"RGB ");
    icc[20..24].copy_from_slice(b"XYZ ");
    icc[36..40].copy_from_slice(b"acsp");
    icc[128..132].copy_from_slice(&4u32.to_be_bytes());

    let tags: [(&[u8; 4], usize, usize); 4] = [
        (b"desc", desc_off, desc_payload.len()),
        (b"rXYZ", r_off, 20),
        (b"gXYZ", g_off, 20),
        (b"bXYZ", b_off, 20),
    ];
    for (idx, (sig, off, sz)) in tags.iter().enumerate() {
        let entry = 132 + idx * 12;
        icc[entry..entry + 4].copy_from_slice(*sig);
        icc[entry + 4..entry + 8].copy_from_slice(&(*off as u32).to_be_bytes());
        icc[entry + 8..entry + 12].copy_from_slice(&(*sz as u32).to_be_bytes());
    }
    icc[desc_off..desc_off + desc_payload.len()].copy_from_slice(&desc_payload);
    icc[r_off..r_off + 20].copy_from_slice(&r_tag);
    icc[g_off..g_off + 20].copy_from_slice(&g_tag);
    icc[b_off..b_off + 20].copy_from_slice(&b_tag);
    icc
}

/// Builds a minimal valid sRGB ICC v2 profile with exact D50 IEC 61966-2-1 primaries.
fn build_minimal_valid_srgb_icc() -> Vec<u8> {
    build_icc_rgb_profile(
        "sRGB IEC61966-2.1",
        (0.4361, 0.2225, 0.0139),
        (0.3851, 0.7169, 0.0971),
        (0.1431, 0.0606, 0.7141),
    )
}

/// Minimal bit writer with JPEG 0xFF -> 0xFF 0x00 byte stuffing.
struct JpegBitWriter {
    bytes: Vec<u8>,
    current: u8,
    bits_in_current: u8,
}

impl JpegBitWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            current: 0,
            bits_in_current: 0,
        }
    }

    fn write_bits(&mut self, value: u32, count: u8) {
        for shift in (0..count).rev() {
            let bit = ((value >> shift) & 1) as u8;
            self.current = (self.current << 1) | bit;
            self.bits_in_current += 1;
            if self.bits_in_current == 8 {
                self.bytes.push(self.current);
                if self.current == 0xFF {
                    self.bytes.push(0x00);
                }
                self.current = 0;
                self.bits_in_current = 0;
            }
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bits_in_current > 0 {
            let pad = 8 - self.bits_in_current;
            self.write_bits((1u32 << pad) - 1, pad);
        }
        self.bytes
    }
}

/// Builds a valid baseline 8x8 4-component Adobe `APP14` (`color_transform = 0` CMYK) JPEG
/// with uniform inverted-Adobe channel samples `(c_inv, m_inv, y_inv, k_inv)`.
///
/// Each channel uses a DC-only 8x8 block where sample value `v` encodes DC = `8 * (v - 128)`.
/// For `v = 248` (`+960`, cat 10) and `v = 8` (`-960`, cat 10), both fit cleanly in 10-bit category `0x0A`.
fn build_adobe_cmyk_jpeg_8x8(c_inv: i16, m_inv: i16, y_inv: i16, k_inv: i16) -> Vec<u8> {
    let mut jpeg = Vec::new();
    // SOI
    jpeg.extend_from_slice(&[0xFF, 0xD8]);
    // APP14 Adobe (version 100, flags0=0, flags1=0, color_transform=0 -> CMYK for 4 components)
    jpeg.extend_from_slice(&[
        0xFF, 0xEE, 0x00, 0x0E, b'A', b'd', b'o', b'b', b'e', 0x00, 0x64, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ]);
    // DQT: table 0, 8-bit precision, all quantization values = 1
    jpeg.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43, 0x00]);
    jpeg.extend_from_slice(&[1u8; 64]);
    // SOF0: 8-bit, 8x8, 4 components (IDs 1..=4, 1x1 sampling, QT 0)
    jpeg.extend_from_slice(&[
        0xFF, 0xC0, 0x00, 0x14, 0x08, 0x00, 0x08, 0x00, 0x08, 0x04, 0x01, 0x11, 0x00, 0x02, 0x11,
        0x00, 0x03, 0x11, 0x00, 0x04, 0x11, 0x00,
    ]);
    // DHT DC table 0:
    //   len 1 -> code 0   => sym 0x00 (DC diff = 0)
    //   len 2 -> code 10  => sym 0x0A (10-bit DC diff, covers +/- 512..1023)
    jpeg.extend_from_slice(&[
        0xFF, 0xC4, 0x00, 0x15, 0x00, // length=21, class=DC(0), id=0
        1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // counts per bit length
        0x00, 0x0A, // symbols
    ]);
    // DHT AC table 0:
    //   len 1 -> code 0   => sym 0x00 (EOB)
    jpeg.extend_from_slice(&[
        0xFF, 0xC4, 0x00, 0x14, 0x10, // length=20, class=AC(1), id=0
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    // counts
        0x00, // EOB symbol
    ]);
    // SOS: 4 components using DC0/AC0, baseline Ss=0, Se=63, Ah/Al=0
    jpeg.extend_from_slice(&[
        0xFF, 0xDA, 0x00, 0x0E, 0x04, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x3F,
        0x00,
    ]);

    let mut bw = JpegBitWriter::new();
    for sample in [c_inv, m_inv, y_inv, k_inv] {
        let dc = 8 * (sample - 128);
        if dc == 0 {
            bw.write_bits(0b0, 1); // DC sym 0x00
        } else {
            // Code `10` (2 bits) => sym 0x0A (10-bit signed magnitude)
            bw.write_bits(0b10, 2);
            let mag_bits = if dc > 0 {
                dc as u32
            } else {
                ((1i32 << 10) - 1 + dc as i32) as u32
            };
            bw.write_bits(mag_bits, 10);
        }
        // AC EOB (`0`, 1 bit)
        bw.write_bits(0b0, 1);
    }
    jpeg.extend_from_slice(&bw.finish());
    // EOI
    jpeg.extend_from_slice(&[0xFF, 0xD9]);
    jpeg
}

#[test]
fn t48_image_orientation_6_rotated_before_exif_strip_and_cmyk_safe() {
    // 1. Default JPEG re-encode quality must be raised from 75 to configurable 90 (`CSE-21`).
    let default_policy = SanitizationPolicy::default();
    assert_eq!(default_policy.jpeg_reencode_quality, 90);
    assert_eq!(DEFAULT_JPEG_REENCODE_QUALITY, 90);

    // 2. Build a non-square 32x16 landscape RGB image whose left half is bright red and
    //    right half is bright blue, then attach an APP1 EXIF Orientation=6 (90° CW) header.
    //    After baking Orientation=6 into pixels and stripping EXIF:
    //    - Dimensions MUST swap from 32x16 -> 16x32
    //    - The former left half (x < 16) rotates 90° CW into the TOP half (y < 16) -> bright red
    //    - The former right half (x >= 16) rotates 90° CW into the BOTTOM half (y >= 16) -> bright blue
    //    - Zero EXIF/APPn metadata remains in the sanitized JPEG
    let mut src_img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::new(32, 16);
    for (x, _y, px) in src_img.enumerate_pixels_mut() {
        *px = if x < 16 {
            Rgb([235, 20, 20])
        } else {
            Rgb([20, 20, 235])
        };
    }
    let mut base_jpeg = Vec::new();
    JpegEncoder::new_with_quality(&mut base_jpeg, 95)
        .encode_image(&DynamicImage::ImageRgb8(src_img))
        .expect("Encode source JPEG");

    for big_endian in [false, true] {
        let mut app1_payload = b"Exif\0\0".to_vec();
        app1_payload.extend_from_slice(&build_tiff_with_orientation(6, big_endian));
        let oriented_jpeg = inject_jpeg_segment(&base_jpeg, 0xE1, &app1_payload);

        let engine = CdrEngine::new(SanitizationPolicy::default());
        let (clean_jpeg, report) = engine
            .sanitize(&oriented_jpeg)
            .expect("Orientation=6 JPEG must sanitize cleanly");

        let scan = ImageSanitizer::scan_jpeg_structure(&clean_jpeg)
            .expect("Sanitized JPEG must be structurally valid");
        assert!(
            !scan.has_metadata,
            "Sanitized JPEG must contain zero residual EXIF/APPn metadata"
        );
        assert_eq!(scan.trailing_overlay_bytes, 0);

        let decoded = image::load_from_memory(&clean_jpeg)
            .expect("Sanitized JPEG must decode cleanly")
            .to_rgb8();
        assert_eq!(
            decoded.dimensions(),
            (16, 32),
            "EXIF Orientation=6 (big_endian={big_endian}) must rotate 32x16 -> 16x32 before EXIF strip"
        );

        let top_px = decoded.get_pixel(8, 6);
        let bottom_px = decoded.get_pixel(8, 26);
        assert!(
            top_px[0] > 180 && top_px[2] < 60,
            "Top half after 90° CW bake must be red, got {top_px:?}"
        );
        assert!(
            bottom_px[2] > 180 && bottom_px[0] < 60,
            "Bottom half after 90° CW bake must be blue, got {bottom_px:?}"
        );

        assert!(
            report
                .stripped_elements
                .iter()
                .any(|item| item.element_type == "IMAGE_EXIF_ORIENTATION_BAKED"
                    && item.location_path == "EXIF_ORIENTATION_6"),
            "Report must document EXIF orientation bake: {:?}",
            report.stripped_elements
        );
        assert!(
            report
                .stripped_elements
                .iter()
                .any(|item| item.element_type == "IMAGE_EXIF_METADATA"),
            "Report must document EXIF strip: {:?}",
            report.stripped_elements
        );
    }

    // Even when `reencode_images: false` with `strip_image_metadata: true`, an Orientation=6 JPEG
    // MUST still bake orientation instead of stripping APP1 and leaving a sideways photo.
    let mut app1_le = b"Exif\0\0".to_vec();
    app1_le.extend_from_slice(&build_tiff_with_orientation(6, false));
    let oriented_jpeg = inject_jpeg_segment(&base_jpeg, 0xE1, &app1_le);
    let lossless_policy = SanitizationPolicy {
        reencode_images: false,
        ..SanitizationPolicy::default()
    };
    let (clean_lossless_baked, lossless_report) = CdrEngine::new(lossless_policy)
        .sanitize(&oriented_jpeg)
        .expect("Lossless policy with EXIF orientation!=1 must bake orientation safely");
    let decoded_baked = image::load_from_memory(&clean_lossless_baked)
        .expect("Baked JPEG must decode")
        .to_rgb8();
    assert_eq!(decoded_baked.dimensions(), (16, 32));
    assert!(lossless_report
        .stripped_elements
        .iter()
        .any(|i| i.element_type == "IMAGE_EXIF_ORIENTATION_BAKED"));

    // 3. Configurable JPEG re-encode quality must genuinely control encoder quality.
    //    Use a high-frequency checkerboard image so quality=95 vs quality=30 visibly diverges in size.
    let mut textured: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::new(64, 64);
    for (x, y, px) in textured.enumerate_pixels_mut() {
        let r = ((x * 37 + y * 17) % 255) as u8;
        let g = ((x * 13 + y * 53) % 255) as u8;
        let b = ((x * 71 + y * 29) % 255) as u8;
        *px = Rgb([r, g, b]);
    }
    let mut textured_jpeg = Vec::new();
    JpegEncoder::new_with_quality(&mut textured_jpeg, 98)
        .encode_image(&DynamicImage::ImageRgb8(textured))
        .expect("Encode textured JPEG");

    let low_q = SanitizationPolicy {
        jpeg_reencode_quality: 30,
        ..SanitizationPolicy::default()
    };
    let high_q = SanitizationPolicy {
        jpeg_reencode_quality: 95,
        ..SanitizationPolicy::default()
    };
    let (low_bytes, _) = CdrEngine::new(low_q)
        .sanitize(&textured_jpeg)
        .expect("Low-quality re-encode");
    let (high_bytes, _) = CdrEngine::new(high_q)
        .sanitize(&textured_jpeg)
        .expect("High-quality re-encode");
    assert!(
        high_bytes.len() > low_bytes.len(),
        "Configurable jpeg_reencode_quality must affect output fidelity (q95={}B vs q30={}B)",
        high_bytes.len(),
        low_bytes.len()
    );

    // 4. Adobe APP14 4-component CMYK JPEG must convert cleanly to non-inverted canonical RGB
    //    under BOTH `reencode_images: true` and `reencode_images: false`.
    //    Adobe inverted CMYK `(c'=248, m'=8, y'=8, k'=248)` represents bright RED (`R~241, G~8, B~8`).
    //    If inverted/corrupted, R would collapse near 0 or turn cyan.
    let cmyk_red_jpeg = build_adobe_cmyk_jpeg_8x8(248, 8, 8, 248);
    let info = ImageSanitizer::extract_jpeg_color_and_exif(&cmyk_red_jpeg);
    assert!(info.has_adobe_app14);
    assert_eq!(info.adobe_color_transform, Some(0));
    assert_eq!(info.sof_components, Some(4));
    assert!(info.is_cmyk_or_ycck());

    for reencode in [true, false] {
        let policy = SanitizationPolicy {
            reencode_images: reencode,
            ..SanitizationPolicy::default()
        };
        let (clean_rgb_jpeg, report) = CdrEngine::new(policy)
            .sanitize(&cmyk_red_jpeg)
            .expect("CMYK Adobe APP14 JPEG must convert cleanly to RGB");

        let clean_info = ImageSanitizer::extract_jpeg_color_and_exif(&clean_rgb_jpeg);
        assert_eq!(
            clean_info.sof_components,
            Some(3),
            "Sanitized output from CMYK input must be 3-component canonical RGB (reencode={reencode})"
        );
        assert!(
            !clean_info.has_adobe_app14,
            "Sanitized canonical RGB JPEG must not rely on APP14"
        );

        let decoded_rgb = image::load_from_memory(&clean_rgb_jpeg)
            .expect("Converted RGB JPEG must decode cleanly")
            .to_rgb8();
        let center = decoded_rgb.get_pixel(4, 4);
        assert!(
            center[0] > 200 && center[1] < 40 && center[2] < 40,
            "Adobe CMYK red must convert to non-inverted RGB red (reencode={reencode}), got {center:?}"
        );
        assert!(
            report
                .stripped_elements
                .iter()
                .any(|item| item.element_type == "JPEG_CMYK_TO_RGB_CONVERTED"),
            "Report must record CMYK -> RGB conversion (reencode={reencode}): {:?}",
            report.stripped_elements
        );
    }

    // 5. ICC profile validation & explicit SanitizationReport documentation:
    //    - Valid sRGB ICC profile -> `VALIDATED_SRGB_ICC_STRIPPED_TO_CANONICAL_SRGB`
    //    - Malformed / non-sRGB ICC profile -> `NON_SRGB_OR_MALFORMED_ICC_STRIPPED`
    let valid_srgb_icc = build_minimal_valid_srgb_icc();
    assert!(ImageSanitizer::is_valid_srgb_icc_profile(&valid_srgb_icc));

    let mut valid_app2 = b"ICC_PROFILE\0".to_vec();
    valid_app2.extend_from_slice(&[1, 1]);
    valid_app2.extend_from_slice(&valid_srgb_icc);
    let jpeg_with_valid_icc = inject_jpeg_segment(&base_jpeg, 0xE2, &valid_app2);

    let (clean_valid_icc, valid_icc_report) = CdrEngine::new(SanitizationPolicy::default())
        .sanitize(&jpeg_with_valid_icc)
        .expect("JPEG with valid sRGB ICC must sanitize cleanly");
    assert!(
        !ImageSanitizer::scan_jpeg_structure(&clean_valid_icc)
            .expect("valid JPEG")
            .has_metadata
    );
    assert!(
        valid_icc_report.stripped_elements.iter().any(|i| {
            i.element_type == "IMAGE_ICC_PROFILE_STRIPPED"
                && i.action_taken == "VALIDATED_SRGB_ICC_STRIPPED_TO_CANONICAL_SRGB"
        }),
        "Valid sRGB ICC strip must be explicitly documented: {:?}",
        valid_icc_report.stripped_elements
    );

    let mut bogus_app2 = b"ICC_PROFILE\0".to_vec();
    bogus_app2.extend_from_slice(&[1, 1]);
    bogus_app2.extend_from_slice(b"NOT_A_REAL_ICC_PROFILE_CMYK_PAYLOAD");
    let jpeg_with_bogus_icc = inject_jpeg_segment(&base_jpeg, 0xE2, &bogus_app2);

    let (_, bogus_icc_report) = CdrEngine::new(SanitizationPolicy::default())
        .sanitize(&jpeg_with_bogus_icc)
        .expect("JPEG with malformed ICC must sanitize cleanly");
    assert!(
        bogus_icc_report.stripped_elements.iter().any(|i| {
            i.element_type == "IMAGE_ICC_PROFILE_STRIPPED"
                && i.action_taken == "NON_SRGB_OR_MALFORMED_ICC_STRIPPED"
        }),
        "Malformed/non-sRGB ICC strip must be explicitly documented: {:?}",
        bogus_icc_report.stripped_elements
    );

    // Wide-gamut Display P3 and Adobe RGB 1998 profiles MUST NOT falsely pass as sRGB!
    let display_p3_icc = build_icc_rgb_profile(
        "Display P3",
        (0.5151, 0.2412, -0.0011),
        (0.2920, 0.6922, 0.0419),
        (0.1571, 0.0666, 0.7841),
    );
    assert!(
        !ImageSanitizer::is_valid_srgb_icc_profile(&display_p3_icc),
        "Display P3 wide-gamut ICC profile must NOT pass sRGB validation"
    );
    let adobe_rgb_spoofed_desc = build_icc_rgb_profile(
        "sRGB spoofed Adobe",
        (0.6097, 0.3111, 0.0195),
        (0.2053, 0.6257, 0.0609),
        (0.1492, 0.0632, 0.7446),
    );
    assert!(
        !ImageSanitizer::is_valid_srgb_icc_profile(&adobe_rgb_spoofed_desc),
        "Adobe RGB 1998 primaries must be rejected even if desc spoofs 'sRGB'"
    );
    let mut p3_app2 = b"ICC_PROFILE\0".to_vec();
    p3_app2.extend_from_slice(&[1, 1]);
    p3_app2.extend_from_slice(&display_p3_icc);
    let jpeg_with_p3_icc = inject_jpeg_segment(&base_jpeg, 0xE2, &p3_app2);
    let (_, p3_report) = CdrEngine::new(SanitizationPolicy::default())
        .sanitize(&jpeg_with_p3_icc)
        .expect("JPEG with Display P3 ICC must sanitize cleanly");
    assert!(
        p3_report.stripped_elements.iter().any(|i| {
            i.element_type == "IMAGE_ICC_PROFILE_STRIPPED"
                && i.action_taken == "NON_SRGB_OR_MALFORMED_ICC_STRIPPED"
        }),
        "Display P3 ICC must be reported as NON_SRGB_OR_MALFORMED_ICC_STRIPPED: {:?}",
        p3_report.stripped_elements
    );
}

#[test]
fn t48_exif_orientation_all_8_transforms_and_malformed_tiff_bounds_safety() {
    // Verify all 8 standard EXIF orientations on an asymmetric 3x2 pixel marker grid:
    //   (0,0)=R, (1,0)=G, (2,0)=B
    //   (0,1)=Y, (1,1)=C, (2,1)=M
    let r = Rgb([255, 0, 0]);
    let g = Rgb([0, 255, 0]);
    let b = Rgb([0, 0, 255]);
    let y = Rgb([255, 255, 0]);
    let c = Rgb([0, 255, 255]);
    let m = Rgb([255, 0, 255]);

    let make_grid = || -> DynamicImage {
        let mut buf = ImageBuffer::new(3, 2);
        buf.put_pixel(0, 0, r);
        buf.put_pixel(1, 0, g);
        buf.put_pixel(2, 0, b);
        buf.put_pixel(0, 1, y);
        buf.put_pixel(1, 1, c);
        buf.put_pixel(2, 1, m);
        DynamicImage::ImageRgb8(buf)
    };

    // Orientation 1: identity (3x2)
    let o1 = ImageSanitizer::apply_exif_orientation(make_grid(), 1);
    assert_eq!(o1.dimensions(), (3, 2));
    assert_eq!(o1.to_rgb8().get_pixel(0, 0), &r);

    // Orientation 2: fliph -> top-left becomes B
    let o2 = ImageSanitizer::apply_exif_orientation(make_grid(), 2);
    assert_eq!(o2.dimensions(), (3, 2));
    assert_eq!(o2.to_rgb8().get_pixel(0, 0), &b);

    // Orientation 3: rotate180 -> top-left becomes M
    let o3 = ImageSanitizer::apply_exif_orientation(make_grid(), 3);
    assert_eq!(o3.dimensions(), (3, 2));
    assert_eq!(o3.to_rgb8().get_pixel(0, 0), &m);

    // Orientation 4: flipv -> top-left becomes Y
    let o4 = ImageSanitizer::apply_exif_orientation(make_grid(), 4);
    assert_eq!(o4.dimensions(), (3, 2));
    assert_eq!(o4.to_rgb8().get_pixel(0, 0), &y);

    // Orientation 5: transpose (2x3) -> (0,0)=R, (1,0)=Y, (0,2)=B
    let o5 = ImageSanitizer::apply_exif_orientation(make_grid(), 5);
    assert_eq!(o5.dimensions(), (2, 3));
    assert_eq!(o5.to_rgb8().get_pixel(0, 0), &r);
    assert_eq!(o5.to_rgb8().get_pixel(1, 0), &y);
    assert_eq!(o5.to_rgb8().get_pixel(0, 2), &b);

    // Orientation 6: rotate90 CW (2x3) -> (0,0)=Y, (1,0)=R, (1,2)=B
    let o6 = ImageSanitizer::apply_exif_orientation(make_grid(), 6);
    assert_eq!(o6.dimensions(), (2, 3));
    assert_eq!(o6.to_rgb8().get_pixel(0, 0), &y);
    assert_eq!(o6.to_rgb8().get_pixel(1, 0), &r);
    assert_eq!(o6.to_rgb8().get_pixel(1, 2), &b);

    // Orientation 7: transverse (2x3) -> (0,0)=M, (1,0)=B, (0,2)=Y
    let o7 = ImageSanitizer::apply_exif_orientation(make_grid(), 7);
    assert_eq!(o7.dimensions(), (2, 3));
    assert_eq!(o7.to_rgb8().get_pixel(0, 0), &m);
    assert_eq!(o7.to_rgb8().get_pixel(1, 0), &b);
    assert_eq!(o7.to_rgb8().get_pixel(0, 2), &y);

    // Orientation 8: rotate270 CW / 90 CCW (2x3) -> (0,0)=B, (1,0)=M, (0,2)=R
    let o8 = ImageSanitizer::apply_exif_orientation(make_grid(), 8);
    assert_eq!(o8.dimensions(), (2, 3));
    assert_eq!(o8.to_rgb8().get_pixel(0, 0), &b);
    assert_eq!(o8.to_rgb8().get_pixel(1, 0), &m);
    assert_eq!(o8.to_rgb8().get_pixel(0, 2), &r);

    // Bounds & malformed TIFF safety (never panics, rejects out-of-range orientation values)
    assert_eq!(ImageSanitizer::parse_tiff_exif_orientation(b""), None);
    assert_eq!(
        ImageSanitizer::parse_tiff_exif_orientation(b"II\x2A\x00\xFF\xFF\xFF\xFF"),
        None
    );
    assert_eq!(
        ImageSanitizer::parse_tiff_exif_orientation(&build_tiff_with_orientation(0, false)),
        None
    );
    assert_eq!(
        ImageSanitizer::parse_tiff_exif_orientation(&build_tiff_with_orientation(9, true)),
        None
    );
    for orient in 1..=8u16 {
        assert_eq!(
            ImageSanitizer::parse_tiff_exif_orientation(&build_tiff_with_orientation(
                orient, false
            )),
            Some(orient)
        );
        assert_eq!(
            ImageSanitizer::parse_tiff_exif_orientation(&build_tiff_with_orientation(orient, true)),
            Some(orient)
        );
    }

    // PNG eXIf Orientation=6 must also bake pixel rotation before metadata strip
    let mut png_src: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::new(16, 8);
    for (x, _y, px) in png_src.enumerate_pixels_mut() {
        *px = if x < 8 {
            Rgb([240, 10, 10])
        } else {
            Rgb([10, 10, 240])
        };
    }
    let mut base_png = Vec::new();
    DynamicImage::ImageRgb8(png_src)
        .write_to(
            &mut std::io::Cursor::new(&mut base_png),
            image::ImageFormat::Png,
        )
        .expect("Encode source PNG");
    // Insert valid CRC-32 `eXIf` chunk right after PNG signature (8B) + IHDR (25B = offset 33)
    let tiff_o6 = build_tiff_with_orientation(6, false);
    let mut crc_input = b"eXIf".to_vec();
    crc_input.extend_from_slice(&tiff_o6);
    let mut crc: u32 = 0xFFFF_FFFF;
    for byte in crc_input {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if (crc & 1) != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    crc ^= 0xFFFF_FFFF;

    let mut png_with_exif = Vec::new();
    png_with_exif.extend_from_slice(&base_png[..33]);
    png_with_exif.extend_from_slice(&(tiff_o6.len() as u32).to_be_bytes());
    png_with_exif.extend_from_slice(b"eXIf");
    png_with_exif.extend_from_slice(&tiff_o6);
    png_with_exif.extend_from_slice(&crc.to_be_bytes());
    png_with_exif.extend_from_slice(&base_png[33..]);

    let (clean_png, png_report) = CdrEngine::new(SanitizationPolicy::default())
        .sanitize(&png_with_exif)
        .expect("PNG with eXIf Orientation=6 must sanitize and bake rotation");
    let decoded_png = image::load_from_memory(&clean_png)
        .expect("Sanitized PNG must decode")
        .to_rgb8();
    assert_eq!(decoded_png.dimensions(), (8, 16));
    assert_eq!(decoded_png.get_pixel(4, 2), &Rgb([240, 10, 10]));
    assert_eq!(decoded_png.get_pixel(4, 12), &Rgb([10, 10, 240]));
    assert!(png_report
        .stripped_elements
        .iter()
        .any(|i| i.element_type == "IMAGE_EXIF_ORIENTATION_BAKED"));
    assert!(
        !ImageSanitizer::scan_png_structure(&clean_png)
            .expect("valid PNG")
            .has_metadata
    );
}
