//! Top-level Rune view orchestration: sticky operational header, persona view router,
//! footer action strip, and root overlay stack (`rune_kit::root`).

pub mod kiosk;
pub mod modals;
pub mod soc_hud;

use rune::tok::motion;
use rune::{Color, Cx, El, ScrollSpec, col, el, row, spacer, text};
use rune_kit::{Button, ButtonVariant, ControlSize, SegmentedControl, root};

use crate::model::{BackendCmd, ConnectionState, ModalState, PersonaMode, SentinelState, ThemeMode};
use crate::theme::SentinelTheme;

pub fn view(s: &SentinelState, _cx: &mut Cx<SentinelState>) -> El {
    let theme = SentinelTheme::for_mode(s.theme);
    let mut overlay_layer: Vec<El> = Vec::new();

    // Build any open accessible modal dialog onto the root overlay layer
    modals::build_modals(s, &theme, &mut overlay_layer);

    let main_body = match s.persona {
        PersonaMode::SocHud => soc_hud::build(s, &theme),
        PersonaMode::Kiosk => kiosk::build(s, &theme),
    };

    let scrollable_canvas = col()
        .key("main-scroll-outer")
        .w_full()
        .grow(1.0)
        .min_h(0.0)
        .child(
            col()
                .key("main-scroll-view")
                .w_full()
                .grow(1.0)
                .min_h(0.0)
                .scroll(ScrollSpec {
                    stick_bottom: false,
                })
                .child(
                    col()
                        .key("main-canvas-center")
                        .w_full()
                        .items_center()
                        .px(24.0)
                        .pt(12.0)
                        .pb(18.0)
                        .child(
                            col()
                                .key("main-canvas-inner")
                                .w_full()
                                .max_w(1320.0)
                                .gap(12.0)
                                .child(main_body),
                        ),
                ),
        );

    let shell = col()
        .key("sentinel-window")
        .role("window")
        .w_full()
        .h_full()
        .fill(theme.canvas_bg)
        .child(build_header(s, &theme))
        .child(scrollable_canvas)
        .child(build_footer(s, &theme));

    root(shell, overlay_layer)
}

fn build_header(s: &SentinelState, theme: &SentinelTheme) -> El {
    let brand_badge = el()
        .key("brand-icon")
        .size(34.0, 34.0)
        .radius(8.0)
        .center()
        .fill(theme.ink_primary)
        .child(
            text("Ω")
                .font(theme.t_brand)
                .color(theme.ink_inverse)
                .a11y_hidden(),
        );

    let version_pill = row()
        .key("version-pill")
        .px(7.0)
        .h(19.0)
        .center()
        .radius(5.0)
        .fill(theme.subtle_bg)
        .border(1.0, theme.border_hairline)
        .child(
            text("v0.1 · Ring 3 · Rune GPU")
                .font(theme.t_caption)
                .color(theme.ink_secondary),
        );

    let brand_group = row()
        .key("brand-group")
        .gap(12.0)
        .center_y()
        .child(brand_badge)
        .child(
            col()
                .gap(1.0)
                .child(
                    row()
                        .gap(8.0)
                        .center_y()
                        .child(
                            text("OmniConnect Sentinel")
                                .font(theme.t_brand)
                                .color(theme.ink_primary),
                        )
                        .child(version_pill),
                )
                .child(
                    text("Zero-Trust Peripheral Interceptor & Sandboxed Pure-Rust CDR Station")
                        .font(theme.t_caption)
                        .color(theme.ink_muted),
                ),
        );

    let (status_label, pill_fg, pill_bg, pill_border) = match &s.connection {
        ConnectionState::DemoFixture => (
            "DEMO MODE — WATERMARKED FIXTURE FEED".to_owned(),
            theme.warn_fg,
            theme.warn_bg,
            theme.warn_border,
        ),
        ConnectionState::Connected => {
            if s.posture.is_compliant {
                (
                    "Ring 3 Posture: Fail-Closed Compliant (Ledger Verified)".to_owned(),
                    theme.safe_fg,
                    theme.safe_bg,
                    theme.safe_border,
                )
            } else {
                (
                    format!(
                        "Ring 3 Agent Active — Posture {}/6 Checks",
                        s.posture.passed_count()
                    ),
                    theme.warn_fg,
                    theme.warn_bg,
                    theme.warn_border,
                )
            }
        }
        ConnectionState::Unauthorized => (
            "AUTH REQUIRED — Click Auth to Exchange Bootstrap Code".to_owned(),
            theme.warn_fg,
            theme.warn_bg,
            theme.warn_border,
        ),
        ConnectionState::Connecting => (
            format!("Connecting to 127.0.0.1:{}...", s.port),
            theme.info_fg,
            theme.info_bg,
            theme.info_border,
        ),
        ConnectionState::Disconnected { retry_in_secs, .. } => (
            format!("DISCONNECTED — NO LIVE DATA (Retry {retry_in_secs}s)"),
            theme.danger_fg,
            theme.danger_bg,
            theme.danger_border,
        ),
    };

    let status_pill = row()
        .key("system-health-pill")
        .role("status")
        .label(status_label.clone())
        .h(28.0)
        .px(10.0)
        .gap(7.0)
        .center_y()
        .radius(999.0)
        .fill(pill_bg)
        .border(1.0, pill_border)
        .child(el().size(7.0, 7.0).radius(3.5).fill(pill_fg).a11y_hidden())
        .child(
            text(status_label)
                .font(theme.t_caption)
                .color(pill_fg)
                .a11y_hidden(),
        );

    let persona_idx = match s.persona {
        PersonaMode::SocHud => 0,
        PersonaMode::Kiosk => 1,
    };

    let persona_switcher = SegmentedControl::new(&["SOC HUD", "Air-Gapped Kiosk"], Some(persona_idx))
        .label("Interface persona switcher")
        .fit()
        .on_pick(|s: &mut SentinelState, idx, tx| {
            s.persona = if idx == 1 {
                PersonaMode::Kiosk
            } else {
                PersonaMode::SocHud
            };
            tx.color_motion(motion::SNAPPY);
        })
        .build(&theme.kit)
        .key("persona-switcher");

    let theme_btn = Button::new(if s.theme == ThemeMode::Dark {
        "Light"
    } else {
        "Dark"
    })
    .variant(ButtonVariant::Outline)
    .control_size(ControlSize::Large)
    .help("Switch between Framed Light and Cyber Ops Dark appearance")
    .on_press_tx(|s: &mut SentinelState, tx| {
        s.theme = match s.theme {
            ThemeMode::Light => ThemeMode::Dark,
            ThemeMode::Dark => ThemeMode::Light,
        };
        tx.color_motion(motion::CALM);
    })
    .build(&theme.kit)
    .key("btn-theme-toggle");

    let auth_btn = Button::new("Session Auth")
        .variant(ButtonVariant::Neutral)
        .control_size(ControlSize::Large)
        .help("Authenticate against localhost sentinel ui with a one-time bootstrap code")
        .on_press(|s: &mut SentinelState| {
            s.modal = ModalState::SessionAuth;
        })
        .build(&theme.kit)
        .key("btn-session-auth");

    col()
        .key("site-header")
        .role("banner")
        .w_full()
        .items_center()
        .fill(theme.sheet_bg)
        .border_sides([0.0, 0.0, 1.0, 0.0], theme.border_hairline)
        .px(24.0)
        .py(9.0)
        .child(
            row()
                .w_full()
                .max_w(1320.0)
                .center_y()
                .gap(10.0)
                .child(brand_group)
                .child(spacer())
                .child(status_pill)
                .child(theme_btn)
                .child(auth_btn)
                .child(persona_switcher),
        )
}

fn build_footer(s: &SentinelState, theme: &SentinelTheme) -> El {
    let scan_btn = Button::new(if s.busy_scan {
        "Scanning Staging..."
    } else {
        "Trigger Staging Scan (/api/v1/scan)"
    })
    .variant(ButtonVariant::Neutral)
    .control_size(ControlSize::Regular)
    .disabled(s.busy_scan)
    .on_press(|s: &mut SentinelState| {
        s.busy_scan = true;
        s.send_cmd(BackendCmd::TriggerScan);
    })
    .build(&theme.kit)
    .key("btn-trigger-scan");

    col()
        .key("site-footer")
        .w_full()
        .items_center()
        .fill(theme.sheet_bg)
        .border_sides([1.0, 0.0, 0.0, 0.0], theme.border_hairline)
        .px(24.0)
        .py(7.0)
        .child(
            row()
                .w_full()
                .max_w(1320.0)
                .center_y()
                .gap(12.0)
                .child(
                    text("OmniConnect Sentinel · Native GPU Rune UI (wgpu + Taffy + AccessKit) · Loopback 127.0.0.1 Only")
                        .font(theme.t_caption)
                        .color(theme.ink_muted),
                )
                .child(spacer())
                .child(scan_btn),
        )
}

/// Shared semantic status pill used across KPI cells, posture checks, and stream items.
pub fn status_pill(
    theme: &SentinelTheme,
    label: impl Into<String>,
    fg: Color,
    bg: Color,
    border: Color,
) -> El {
    let text_str = label.into();
    row()
        .px(8.0)
        .h(20.0)
        .center()
        .radius(5.0)
        .fill(bg)
        .border(1.0, border)
        .child(text(text_str).font(theme.t_caption).color(fg))
}
