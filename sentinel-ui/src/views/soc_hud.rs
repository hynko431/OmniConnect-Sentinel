//! SOC Analyst HUD surface (`Operate` mode):
//! 4-column unified KPI strip + 7fr/5fr operational grid with GPU USB schematic,
//! 6-check Posture Gate matrix, MITRE ATT&CK inspector, 64-block NIST 800-88 sanitizer,
//! and live CDR/Audit event stream.

use rune::tok::motion;
use rune::{Color, El, col, el, row, text};
use rune_kit::{Button, ButtonVariant, ControlSize, Switch};

use crate::model::{BackendCmd, MITRE_TECHNIQUES, ModalState, SentinelState};
use crate::schematic::usb_bus_schematic;
use crate::theme::SentinelTheme;
use crate::views::status_pill;

pub fn build(s: &SentinelState, theme: &SentinelTheme) -> El {
    col()
        .key("soc-hud-view")
        .role("main")
        .w_full()
        .gap(12.0)
        .child(build_kpi_strip(s, theme))
        .child(
            row()
                .key("soc-two-col")
                .w_full()
                .gap(12.0)
                .items_start()
                .child(
                    col()
                        .key("soc-left-col")
                        .grow(7.0)
                        .min_w(0.0)
                        .gap(12.0)
                        .child(build_usb_isolation_card(s, theme))
                        .child(build_posture_and_mitre_card(s, theme)),
                )
                .child(
                    col()
                        .key("soc-right-col")
                        .grow(5.0)
                        .min_w(0.0)
                        .gap(12.0)
                        .child(build_shredder_card(s, theme))
                        .child(build_cdr_stream_card(s, theme)),
                ),
        )
}

fn build_kpi_strip(s: &SentinelState, theme: &SentinelTheme) -> El {
    let cdr_badge = status_pill(
        theme,
        format!("Workers Active: {}", s.workers.active),
        theme.safe_fg,
        theme.safe_bg,
        theme.safe_border,
    );

    let vault_badge = if s.audit_ledger_verified {
        status_pill(
            theme,
            "Ledger: ECDSA VERIFIED",
            theme.safe_fg,
            theme.safe_bg,
            theme.safe_border,
        )
    } else {
        status_pill(
            theme,
            "Ledger: UNVERIFIED / OFFLINE",
            theme.warn_fg,
            theme.warn_bg,
            theme.warn_border,
        )
    };

    let (pin_text, pin_color, pin_badge) = if s.bus_hold_active {
        (
            "HELD OFFLINE",
            theme.safe_fg,
            status_pill(
                theme,
                "I1 Pre-Mount Hold Active",
                theme.safe_fg,
                theme.safe_bg,
                theme.safe_border,
            ),
        )
    } else {
        (
            "RING 3 CDR",
            theme.info_fg,
            status_pill(
                theme,
                "ShadowCache + ProjFS/FUSE",
                theme.info_fg,
                theme.info_bg,
                theme.info_border,
            ),
        )
    };

    let passed = s.posture.passed_count();
    let posture_badge = if s.posture.is_compliant {
        status_pill(
            theme,
            "✓ AutoMount Off · Compliant",
            theme.safe_fg,
            theme.safe_bg,
            theme.safe_border,
        )
    } else {
        status_pill(
            theme,
            format!("⚠ {passed}/6 Posture Checks"),
            theme.warn_fg,
            theme.warn_bg,
            theme.warn_border,
        )
    };

    row()
        .key("kpi-strip")
        .w_full()
        .radius(12.0)
        .fill(theme.sheet_bg)
        .border(1.0, theme.border_hairline)
        .child(kpi_cell(
            theme,
            "kpi-cdr",
            "Files Cleaned (CDR)",
            "AppContainer",
            &s.files_cleaned.to_string(),
            "payloads",
            theme.ink_primary,
            false,
            cdr_badge,
            true,
        ))
        .child(kpi_cell(
            theme,
            "kpi-vault",
            "Quarantine Vault",
            "SNTLQV02 AEAD",
            &s.quarantine_count.to_string(),
            "sealed .quar",
            if s.quarantine_count > 0 {
                theme.danger_fg
            } else {
                theme.ink_primary
            },
            false,
            vault_badge,
            true,
        ))
        .child(kpi_cell(
            theme,
            "kpi-bus",
            "USB Bus Interlock",
            "Software Gate",
            pin_text,
            "",
            pin_color,
            true,
            pin_badge,
            true,
        ))
        .child(kpi_cell(
            theme,
            "kpi-posture",
            "Posture Compliance",
            "Ring 3 Userspace",
            &format!("{passed} / 6"),
            "checks",
            theme.ink_primary,
            false,
            posture_badge,
            false,
        ))
}

#[allow(clippy::too_many_arguments)]
fn kpi_cell(
    theme: &SentinelTheme,
    key: &str,
    title: &str,
    note: &str,
    value: &str,
    unit: &str,
    val_color: Color,
    is_pin: bool,
    badge: El,
    right_border: bool,
) -> El {
    let mut val_row = row().gap(6.0).items_end().child(
        text(value)
            .font(if is_pin { theme.t_kpi_pin } else { theme.t_kpi })
            .color(val_color),
    );
    if !unit.is_empty() {
        val_row = val_row.child(text(unit).font(theme.t_caption).color(theme.ink_muted).pb(3.0));
    }

    let mut cell = col()
        .key(key)
        .grow(1.0)
        .min_w(0.0)
        .px(16.0)
        .py(10.0)
        .gap(4.0)
        .child(
            row()
                .w_full()
                .justify_between()
                .center_y()
                .child(text(title).font(theme.t_label).color(theme.ink_secondary))
                .child(text(note).font(theme.t_caption).color(theme.ink_muted)),
        )
        .child(val_row)
        .child(row().child(badge));

    if right_border {
        cell = cell.border_sides([0.0, 1.0, 0.0, 0.0], theme.border_hairline);
    }
    cell
}

fn build_usb_isolation_card(s: &SentinelState, theme: &SentinelTheme) -> El {
    let refresh_btn = Button::new("Refresh Bus")
        .variant(ButtonVariant::Outline)
        .control_size(ControlSize::Regular)
        .on_press(|s: &mut SentinelState| {
            s.send_cmd(BackendCmd::PollNow);
        })
        .build(&theme.kit)
        .key("btn-refresh-bus");

    let hold_switch = Switch::new(s.bus_hold_active)
        .label("Toggle Pre-Mount Bus Hold Preview")
        .hide_label()
        .control_size(ControlSize::Regular)
        .on_toggle_tx(|s: &mut SentinelState, tx| {
            s.bus_hold_active = !s.bus_hold_active;
            tx.color_motion(motion::SNAPPY);
        })
        .build(&theme.kit)
        .key("switch-bus-hold");

    let hold_bar = row()
        .key("bus-interlock-bar")
        .w_full()
        .px(12.0)
        .py(9.0)
        .gap(10.0)
        .center_y()
        .radius(8.0)
        .fill(theme.surface_elevated)
        .border(1.0, theme.border_hairline)
        .child(
            col()
                .grow(1.0)
                .min_w(0.0)
                .gap(4.0)
                .child(
                    row()
                        .gap(8.0)
                        .center_y()
                        .child(
                            text("Logical USB Bus Isolation (MountMgr Hold Preview)")
                                .font(theme.t_label)
                                .color(theme.ink_primary),
                        )
                        .child(if s.bus_hold_active {
                            status_pill(
                                theme,
                                "DATA PATH HELD OFFLINE",
                                theme.safe_fg,
                                theme.safe_bg,
                                theme.safe_border,
                            )
                        } else {
                            status_pill(
                                theme,
                                "RING 3 CDR PIPELINE ACTIVE",
                                theme.info_fg,
                                theme.info_bg,
                                theme.info_border,
                            )
                        }),
                )
                .child(
                    text("Software pre-mount hold blocks volume assignment (I1). Note: physical D+/D- copper isolation requires an external hardware relay.")
                        .font(theme.t_caption)
                        .color(theme.ink_secondary)
                        .wrap(),
                ),
        )
        .child(hold_switch);

    let (bus_class, gate_mode, hw_sensor, attached_vol) = s.bus_telemetry_readout();

    let telemetry_strip = row()
        .key("bus-telemetry-strip")
        .w_full()
        .gap(10.0)
        .child(telemetry_tile(theme, "Bus Class", bus_class, false))
        .child(telemetry_tile(theme, "Gate State", gate_mode, false))
        .child(telemetry_tile(theme, "Power Sensor", hw_sensor, false))
        .child(telemetry_tile(theme, "Attached Volume", &attached_vol, true));

    card_shell(
        theme,
        "card-usb-isolation",
        "USB Bus Isolation & Pre-Mount Interlock (I1)",
        "GPU vector schematic of BusTypeUsb pre-mount hold and Ring 3 ShadowCache boundary",
        Some(refresh_btn),
    )
    .child(usb_bus_schematic(theme, s.bus_hold_active))
    .child(hold_bar)
    .child(telemetry_strip)
}

fn telemetry_tile(theme: &SentinelTheme, label: &str, value: &str, wide: bool) -> El {
    let mut tile = col()
        .grow(if wide { 1.8 } else { 1.0 })
        .min_w(0.0)
        .px(10.0)
        .py(8.0)
        .gap(3.0)
        .radius(6.0)
        .fill(theme.subtle_bg)
        .border(1.0, theme.border_hairline)
        .child(text(label).font(theme.t_caption).color(theme.ink_muted))
        .child(
            text(value)
                .font(theme.t_mono_bold)
                .color(theme.ink_primary)
                .truncate(),
        );
    if wide {
        tile = tile.key("telemetry-attached-volume");
    }
    tile
}

fn build_posture_and_mitre_card(s: &SentinelState, theme: &SentinelTheme) -> El {
    let p = &s.posture;
    let checks = [
        ("AutoMount Off", p.automount_disabled),
        ("Volumes Offline", p.removable_volumes_offline),
        ("User Deny Policy", p.user_deny_policy_present),
        ("Install Restrict", p.install_restrictions_active),
        ("Write Protect", p.write_protect_active),
        ("Overall Compliant", p.is_compliant),
    ];

    let posture_row_1 = row()
        .w_full()
        .gap(8.0)
        .children(checks[0..3].iter().map(|(lbl, ok)| posture_chip(theme, lbl, *ok)));
    let posture_row_2 = row()
        .w_full()
        .gap(8.0)
        .children(checks[3..6].iter().map(|(lbl, ok)| posture_chip(theme, lbl, *ok)));

    let mitre_row_1 = row()
        .w_full()
        .gap(10.0)
        .child(mitre_card(theme, 0))
        .child(mitre_card(theme, 1));
    let mitre_row_2 = row()
        .w_full()
        .gap(10.0)
        .child(mitre_card(theme, 2))
        .child(mitre_card(theme, 3));

    let badge = status_pill(
        theme,
        "4 Mitigations · Click to Inspect",
        theme.safe_fg,
        theme.safe_bg,
        theme.safe_border,
    );

    card_shell(
        theme,
        "card-mitre",
        "Hardware Posture Gate & MITRE ATT&CK® Defense Matrix",
        "Live 6-check OS posture verification paired with Ring 3 peripheral attack mitigations",
        Some(badge),
    )
    .child(
        col()
            .key("posture-matrix")
            .w_full()
            .gap(6.0)
            .child(posture_row_1)
            .child(posture_row_2),
    )
    .child(el().w_full().h(1.0).fill(theme.border_hairline).a11y_hidden())
    .child(
        col()
            .key("mitre-grid")
            .w_full()
            .gap(10.0)
            .child(mitre_row_1)
            .child(mitre_row_2),
    )
}

fn posture_chip(theme: &SentinelTheme, label: &str, ok: bool) -> El {
    let (fg, bg, border, mark) = if ok {
        (theme.safe_fg, theme.safe_bg, theme.safe_border, "✓")
    } else {
        (theme.warn_fg, theme.warn_bg, theme.warn_border, "!")
    };
    row()
        .grow(1.0)
        .min_w(0.0)
        .px(10.0)
        .h(26.0)
        .gap(6.0)
        .center_y()
        .radius(6.0)
        .fill(bg)
        .border(1.0, border)
        .child(text(mark).font(theme.t_mono_bold).color(fg))
        .child(text(label).font(theme.t_caption).color(fg).truncate())
}

fn mitre_card(theme: &SentinelTheme, idx: usize) -> El {
    let info = MITRE_TECHNIQUES[idx];
    let id = info.id;

    col()
        .key(format!("mitre-chip-{id}"))
        .role("button")
        .label(format!("Inspect {} {}", info.id, info.full_title))
        .focusable(true)
        .grow(1.0)
        .min_w(0.0)
        .px(10.0)
        .py(8.0)
        .gap(3.0)
        .radius(8.0)
        .fill(theme.subtle_bg)
        .border(1.0, theme.border_hairline)
        .hover(theme.kit.c.hover)
        .press(theme.kit.c.pressed)
        .press_scale(0.985)
        .on_press(move |s: &mut SentinelState| {
            s.modal = ModalState::Mitre(id);
        })
        .child(
            row()
                .w_full()
                .justify_between()
                .center_y()
                .child(
                    row()
                        .px(6.0)
                        .h(18.0)
                        .center()
                        .radius(4.0)
                        .fill(theme.sheet_bg)
                        .border(1.0, theme.border_strong)
                        .child(text(info.id).font(theme.t_mono_bold).color(theme.ink_primary)),
                )
                .child(
                    text(format!("✓ {}", info.status))
                        .font(theme.t_caption)
                        .color(theme.safe_fg),
                ),
        )
        .child(
            text(info.short_name)
                .font(theme.t_label)
                .color(theme.ink_primary),
        )
        .child(
            text(info.summary)
                .font(theme.t_caption)
                .color(theme.ink_secondary)
                .wrap(),
        )
}

fn build_shredder_card(s: &SentinelState, theme: &SentinelTheme) -> El {
    let shred_btn = Button::new(if s.busy_shred {
        "Shredding..."
    } else {
        "Execute Live Clear"
    })
    .variant(ButtonVariant::Contrast)
    .control_size(ControlSize::Regular)
    .disabled(s.busy_shred)
    .on_press(|s: &mut SentinelState| {
        s.modal = ModalState::ShredConfirm;
    })
    .build(&theme.kit)
    .key("btn-initiate-shred");

    let target_label = s
        .last_shred_receipt
        .as_ref()
        .filter(|r| !r.original_path.is_empty())
        .map(|r| r.original_path.as_str())
        .unwrap_or("Awaiting Live Staging Canary Receipt");

    let passes = s
        .last_shred_receipt
        .as_ref()
        .map(|r| r.passes_completed)
        .unwrap_or(0);

    let cell_color = match passes {
        0 => theme.sector_idle,
        1 => theme.sector_pass1,
        2 => theme.sector_pass2,
        _ => theme.sector_pass3,
    };

    let mut grid_rows = col()
        .key("sector-grid-64")
        .role("grid")
        .label("64-block logical sector overwrite map")
        .w_full()
        .gap(4.0);

    for r in 0..8 {
        let mut row_el = row().w_full().gap(4.0);
        for c in 0..8 {
            let idx = r * 8 + c;
            row_el = row_el.child(
                el().key(format!("sector-{idx}"))
                    .grow(1.0)
                    .h(12.0)
                    .radius(2.5)
                    .fill(cell_color)
                    .motion(motion::SNAPPY)
                    .a11y_hidden(),
            );
        }
        grid_rows = grid_rows.child(row_el);
    }

    let legend = row()
        .w_full()
        .justify_between()
        .pt(2.0)
        .child(legend_dot(theme, "Unmodified", theme.sector_idle))
        .child(legend_dot(theme, "Pass 1 (0x00)", theme.sector_pass1))
        .child(legend_dot(theme, "Pass 2 (0xFF)", theme.sector_pass2))
        .child(legend_dot(theme, "Pass 3 (CSPRNG)", theme.sector_pass3));

    card_shell(
        theme,
        "card-shredder",
        "NIST SP 800-88 Sector Sanitizer",
        "3-pass write-through logical clear + SHA-256 read-back verify (honest Flash FTL class)",
        Some(shred_btn),
    )
    .child(
        col()
            .w_full()
            .padding(12.0)
            .gap(10.0)
            .radius(8.0)
            .fill(theme.subtle_bg)
            .border(1.0, theme.border_hairline)
            .child(
                col()
                    .gap(3.0)
                    .child(
                        text(format!("Target: {target_label}"))
                            .font(theme.t_mono)
                            .color(theme.ink_primary)
                            .truncate(),
                    )
                    .child(
                        text(format!("Status: {}", s.shred_status_msg))
                            .font(theme.t_caption)
                            .color(if s.shred_status_is_error {
                                theme.danger_fg
                            } else if passes >= 3 {
                                theme.safe_fg
                            } else {
                                theme.ink_secondary
                            })
                            .wrap(),
                    ),
            )
            .child(grid_rows)
            .child(legend),
    )
}

fn legend_dot(theme: &SentinelTheme, label: &str, swatch: Color) -> El {
    row()
        .gap(5.0)
        .center_y()
        .child(el().size(9.0, 9.0).radius(2.5).fill(swatch).a11y_hidden())
        .child(text(label).font(theme.t_caption).color(theme.ink_secondary))
}

fn build_cdr_stream_card(s: &SentinelState, theme: &SentinelTheme) -> El {
    let inspect_btn = Button::new("Inspect Telemetry")
        .variant(ButtonVariant::Outline)
        .control_size(ControlSize::Regular)
        .on_press(|s: &mut SentinelState| {
            s.modal = ModalState::CdrTelemetry;
        })
        .build(&theme.kit)
        .key("btn-inspect-cdr");

    let mut list = col().key("cdr-stream-list").w_full().gap(6.0);
    for item in s.stream_items.iter().take(4) {
        let badge = if item.is_alert {
            status_pill(
                theme,
                &item.badge_text,
                theme.danger_fg,
                theme.danger_bg,
                theme.danger_border,
            )
        } else {
            status_pill(
                theme,
                &item.badge_text,
                theme.safe_fg,
                theme.safe_bg,
                theme.safe_border,
            )
        };

        list = list.child(
            row()
                .key(format!("stream-{}", item.id))
                .w_full()
                .px(10.0)
                .py(7.0)
                .gap(10.0)
                .center_y()
                .radius(7.0)
                .fill(theme.subtle_bg)
                .border(1.0, theme.border_hairline)
                .child(
                    col()
                        .grow(1.0)
                        .min_w(0.0)
                        .gap(2.0)
                        .child(
                            text(&item.title)
                                .font(theme.t_label)
                                .color(theme.ink_primary)
                                .truncate(),
                        )
                        .child(
                            text(&item.detail)
                                .font(theme.t_caption)
                                .color(theme.ink_secondary)
                                .truncate(),
                        ),
                )
                .child(badge),
        );
    }

    card_shell(
        theme,
        "card-cdr-stream",
        "Deep CDR Sanitization & Audit Stream",
        "Live backend event feed from 127.0.0.1 /api/v1/ws (zero fabricated events when offline)",
        Some(inspect_btn),
    )
    .child(list)
}

fn card_shell(
    theme: &SentinelTheme,
    key: &str,
    title: &str,
    subtitle: &str,
    action: Option<El>,
) -> El {
    let mut header = row()
        .w_full()
        .items_start()
        .gap(12.0)
        .child(
            col()
                .grow(1.0)
                .min_w(0.0)
                .gap(2.0)
                .child(text(title).font(theme.t_h2).color(theme.ink_primary))
                .child(text(subtitle).font(theme.t_caption).color(theme.ink_muted).truncate()),
        );
    if let Some(act) = action {
        header = header.child(act);
    }

    col()
        .key(key)
        .w_full()
        .px(14.0)
        .py(12.0)
        .gap(10.0)
        .radius(12.0)
        .fill(theme.sheet_bg)
        .border(1.0, theme.border_hairline)
        .child(header)
}
