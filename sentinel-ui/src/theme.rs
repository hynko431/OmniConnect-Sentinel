//! Sentinel OKLCH Design System wrapping `rune-kit::Kit` with dual-mode palettes
//! (Framed Sheet Light / Cyber Ops Dark), tabular figures, and crisp status semantics.

use rune::color::hex;
use rune::tok::{Family, TextStyle};
use rune::{Color, oklch, oklcha};
use rune_kit::{Kit, PaletteSeed};

use crate::model::ThemeMode;

fn must_hex(s: &str) -> Color {
    hex(s).unwrap_or(Color::BLACK)
}

/// Complete design token bundle for one Sentinel appearance.
pub struct SentinelTheme {
    pub kit: Kit,

    // Framed Sheet Surfaces
    pub canvas_bg: Color,
    pub sheet_bg: Color,
    pub subtle_bg: Color,
    pub surface_elevated: Color,
    pub border_hairline: Color,
    pub border_strong: Color,

    // Ink Hierarchy
    pub ink_primary: Color,
    pub ink_secondary: Color,
    pub ink_muted: Color,
    pub ink_inverse: Color,

    // Semantic Data Hues (kept strictly on status/data, < 5% surface area)
    pub safe_fg: Color,
    pub safe_bg: Color,
    pub safe_border: Color,

    pub warn_fg: Color,
    pub warn_bg: Color,
    pub warn_border: Color,

    pub danger_fg: Color,
    pub danger_bg: Color,
    pub danger_border: Color,

    pub info_fg: Color,
    pub info_bg: Color,
    pub info_border: Color,

    // Sector Shredder Swatches
    pub sector_idle: Color,
    pub sector_pass1: Color,
    pub sector_pass2: Color,
    pub sector_pass3: Color,

    // Typography
    pub t_brand: TextStyle,
    pub t_h2: TextStyle,
    pub t_kpi: TextStyle,
    pub t_kpi_pin: TextStyle,
    pub t_body: TextStyle,
    pub t_label: TextStyle,
    pub t_caption: TextStyle,
    pub t_mono: TextStyle,
    pub t_mono_bold: TextStyle,
    pub t_kiosk_title: TextStyle,
    pub t_kiosk_step: TextStyle,
}

impl SentinelTheme {
    pub fn for_mode(mode: ThemeMode) -> Self {
        let dark = matches!(mode, ThemeMode::Dark);
        let (canvas_bg, sheet_bg, subtle_bg, surface_elevated, border_hairline, border_strong) =
            if dark {
                (
                    oklch(0.155, 0.008, 255.0),
                    oklch(0.195, 0.009, 255.0),
                    oklch(0.235, 0.010, 255.0),
                    oklch(0.265, 0.012, 255.0),
                    oklcha(0.95, 0.005, 255.0, 0.10),
                    oklcha(0.95, 0.005, 255.0, 0.20),
                )
            } else {
                (
                    must_hex("#f8fafc"),
                    must_hex("#ffffff"),
                    must_hex("#f1f5f9"),
                    must_hex("#f8fafc"),
                    must_hex("#e2e8f0"),
                    must_hex("#cbd5e1"),
                )
            };

        let (ink_primary, ink_secondary, ink_muted, ink_inverse) = if dark {
            (
                oklch(0.955, 0.004, 255.0),
                oklch(0.755, 0.009, 255.0),
                oklch(0.60, 0.010, 255.0),
                oklch(0.15, 0.006, 255.0),
            )
        } else {
            (
                must_hex("#0f172a"),
                must_hex("#475569"),
                must_hex("#64748b"),
                must_hex("#ffffff"),
            )
        };

        let accent = if dark {
            must_hex("#38bdf8")
        } else {
            must_hex("#0f172a")
        };

        let mut kit = Kit::from_palette(PaletteSeed {
            bg: sheet_bg,
            fg: ink_primary,
            accent,
        });
        kit.c.page = canvas_bg;
        kit.c.border_base = border_hairline;
        kit.c.border_strong = border_strong;

        let (safe_fg, safe_bg, safe_border) = if dark {
            (
                must_hex("#34d399"),
                oklcha(0.45, 0.11, 160.0, 0.22),
                oklcha(0.68, 0.14, 160.0, 0.40),
            )
        } else {
            (
                must_hex("#059669"),
                must_hex("#ecfdf5"),
                must_hex("#a7f3d0"),
            )
        };

        let (warn_fg, warn_bg, warn_border) = if dark {
            (
                must_hex("#fbbf24"),
                oklcha(0.50, 0.12, 80.0, 0.22),
                oklcha(0.75, 0.14, 80.0, 0.42),
            )
        } else {
            (
                must_hex("#b45309"),
                must_hex("#fffbeb"),
                must_hex("#fde68a"),
            )
        };

        let (danger_fg, danger_bg, danger_border) = if dark {
            (
                must_hex("#f87171"),
                oklcha(0.45, 0.15, 25.0, 0.24),
                oklcha(0.66, 0.16, 25.0, 0.45),
            )
        } else {
            (
                must_hex("#dc2626"),
                must_hex("#fef2f2"),
                must_hex("#fecaca"),
            )
        };

        let (info_fg, info_bg, info_border) = if dark {
            (
                must_hex("#38bdf8"),
                oklcha(0.46, 0.11, 235.0, 0.24),
                oklcha(0.70, 0.13, 235.0, 0.42),
            )
        } else {
            (
                must_hex("#0284c7"),
                must_hex("#f0f9ff"),
                must_hex("#bae6fd"),
            )
        };

        let (sector_idle, sector_pass1, sector_pass2, sector_pass3) = if dark {
            (
                oklch(0.28, 0.01, 255.0),
                must_hex("#0284c7"),
                must_hex("#d97706"),
                must_hex("#10b981"),
            )
        } else {
            (
                must_hex("#e2e8f0"),
                must_hex("#0ea5e9"),
                must_hex("#f59e0b"),
                must_hex("#059669"),
            )
        };

        Self {
            kit,
            canvas_bg,
            sheet_bg,
            subtle_bg,
            surface_elevated,
            border_hairline,
            border_strong,
            ink_primary,
            ink_secondary,
            ink_muted,
            ink_inverse,
            safe_fg,
            safe_bg,
            safe_border,
            warn_fg,
            warn_bg,
            warn_border,
            danger_fg,
            danger_bg,
            danger_border,
            info_fg,
            info_bg,
            info_border,
            sector_idle,
            sector_pass1,
            sector_pass2,
            sector_pass3,
            t_brand: TextStyle::new(15.5, 700.0).tracking(-0.2).lh(20.0),
            t_h2: TextStyle::new(14.5, 700.0).tracking(-0.1).lh(19.0),
            t_kpi: TextStyle::new(26.0, 700.0)
                .tracking(-0.5)
                .lh(30.0)
                .features("'tnum' 1"),
            t_kpi_pin: TextStyle::new(20.0, 700.0)
                .tracking(-0.2)
                .lh(28.0)
                .features("'tnum' 1"),
            t_body: TextStyle::new(12.5, 400.0).lh(17.5),
            t_label: TextStyle::new(11.5, 600.0).lh(15.0),
            t_caption: TextStyle::new(11.0, 500.0).lh(14.5),
            t_mono: TextStyle::new(11.5, 500.0)
                .family(Family::SystemMono)
                .lh(16.0)
                .features("'tnum' 1"),
            t_mono_bold: TextStyle::new(12.0, 700.0)
                .family(Family::SystemMono)
                .lh(16.0)
                .features("'tnum' 1"),
            t_kiosk_title: TextStyle::new(26.0, 700.0).tracking(-0.4).lh(32.0),
            t_kiosk_step: TextStyle::new(17.0, 700.0).tracking(-0.2).lh(22.0),
        }
    }
}
