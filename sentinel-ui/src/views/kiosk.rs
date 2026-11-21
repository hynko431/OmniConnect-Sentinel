//! Air-Gapped Walk-Up Kiosk surface (Mode A — High-Contrast Sunlight-Readable IEC 62443 Station).

use rune::tok::motion;
use rune::{El, col, el, row, text};
use rune_kit::{Button, ButtonVariant, ControlSize};

use crate::model::{BackendCmd, KioskStage, SentinelState};
use crate::theme::SentinelTheme;
use crate::views::status_pill;

pub fn build(s: &SentinelState, theme: &SentinelTheme) -> El {
    let posture_pill = if s.posture.is_compliant {
        status_pill(
            theme,
            "KioskEnforcer Gate: 6/6 POSTURE VERIFIED",
            theme.safe_fg,
            theme.safe_bg,
            theme.safe_border,
        )
    } else {
        status_pill(
            theme,
            format!(
                "KioskEnforcer Gate: NON-COMPLIANT ({}/6) — Session Blocked",
                s.posture.passed_count()
            ),
            theme.danger_fg,
            theme.danger_bg,
            theme.danger_border,
        )
    };

    let banner = col()
        .key("kiosk-banner")
        .w_full()
        .padding(24.0)
        .gap(10.0)
        .items_center()
        .radius(14.0)
        .fill(theme.sheet_bg)
        .border(1.5, theme.border_strong)
        .child(posture_pill)
        .child(
            text("Air-Gapped USB Inspection Station")
                .font(theme.t_kiosk_title)
                .color(theme.ink_primary),
        )
        .child(
            text("Inspect and sanitize removable media inside the isolated staging boundary before transferring approved artifacts into the OT/ICS control zone.")
                .font(theme.t_body)
                .color(theme.ink_secondary)
                .wrap(),
        );

    let step1_active = matches!(
        s.kiosk_stage,
        KioskStage::InsertDrive | KioskStage::BlockedError
    );
    let step2_active = matches!(s.kiosk_stage, KioskStage::Scanning);
    let step3_active = matches!(s.kiosk_stage, KioskStage::VerifiedClean);

    let steps_row = row()
        .key("kiosk-steps-grid")
        .w_full()
        .gap(16.0)
        .child(kiosk_step_card(
            theme,
            "kiosk-step-1",
            "1",
            "Insert Untrusted Media",
            "Connect vendor flash drive to the isolated bay. OS auto-mount remains suppressed fail-closed.",
            step1_active,
            false,
        ))
        .child(kiosk_step_card(
            theme,
            "kiosk-step-2",
            "2",
            "Sandboxed CDR & Threat Scan",
            "Universal scanner + AppContainer CDR worker inspect payloads and quarantine active threats to .quar vault.",
            step2_active,
            false,
        ))
        .child(kiosk_step_card(
            theme,
            "kiosk-step-3",
            "3",
            "Verified Clean & Audit Receipt",
            "Approved outputs pass integrity verification with an ECDSA P-256 signed ledger record. Session artifacts wipe on exit.",
            step3_active,
            step3_active,
        ));

    let scan_btn = Button::new(if s.busy_scan || step2_active {
        "Executing Kiosk Inspection..."
    } else {
        "Execute Kiosk Inspection"
    })
    .variant(ButtonVariant::Contrast)
    .control_size(ControlSize::ExtraLarge)
    .disabled(s.busy_scan || step2_active)
    .on_press(|s: &mut SentinelState| {
        s.busy_scan = true;
        s.kiosk_stage = KioskStage::Scanning;
        s.kiosk_summary = "Running live backend inspection via POST /api/v1/scan...".into();
        s.send_cmd(BackendCmd::TriggerKioskScan);
    })
    .build(&theme.kit)
    .key("btn-kiosk-scan");

    let reset_btn = Button::new("Reset Kiosk Session")
        .variant(ButtonVariant::Outline)
        .control_size(ControlSize::ExtraLarge)
        .disabled(matches!(s.kiosk_stage, KioskStage::InsertDrive))
        .on_press(|s: &mut SentinelState| {
            s.kiosk_stage = KioskStage::InsertDrive;
            s.kiosk_summary =
                "Session reset. Ready for next air-gapped inspection cycle.".into();
        })
        .build(&theme.kit)
        .key("btn-kiosk-reset");

    let (summary_fg, summary_bg, summary_border) = match s.kiosk_stage {
        KioskStage::VerifiedClean => (theme.safe_fg, theme.safe_bg, theme.safe_border),
        KioskStage::BlockedError => (theme.danger_fg, theme.danger_bg, theme.danger_border),
        KioskStage::Scanning => (theme.info_fg, theme.info_bg, theme.info_border),
        KioskStage::InsertDrive => (theme.ink_secondary, theme.subtle_bg, theme.border_hairline),
    };

    let status_card = col()
        .key("kiosk-status-receipt")
        .w_full()
        .padding(16.0)
        .gap(6.0)
        .radius(10.0)
        .fill(summary_bg)
        .border(1.5, summary_border)
        .child(
            text("Live Kiosk Session Telemetry & Verification Gate")
                .font(theme.t_label)
                .color(summary_fg),
        )
        .child(
            text(&s.kiosk_summary)
                .font(theme.t_body)
                .color(summary_fg)
                .wrap(),
        )
        .child(
            text("Safety Policy: Step 3 illuminates ONLY when backend reports complete == true AND threats == 0. Unsupported formats remain withheld fail-closed.")
                .font(theme.t_caption)
                .color(theme.ink_muted)
                .wrap(),
        );

    col()
        .key("kiosk-view")
        .role("main")
        .w_full()
        .gap(20.0)
        .child(banner)
        .child(steps_row)
        .child(
            row()
                .w_full()
                .center()
                .gap(14.0)
                .child(scan_btn)
                .child(reset_btn),
        )
        .child(status_card)
}

fn kiosk_step_card(
    theme: &SentinelTheme,
    key: &str,
    num: &str,
    heading: &str,
    body: &str,
    active: bool,
    verified: bool,
) -> El {
    let border_c = if verified {
        theme.safe_fg
    } else if active {
        theme.ink_primary
    } else {
        theme.border_hairline
    };

    let num_bg = if verified {
        theme.safe_fg
    } else if active {
        theme.ink_primary
    } else {
        theme.subtle_bg
    };

    let num_fg = if verified || active {
        theme.ink_inverse
    } else {
        theme.ink_secondary
    };

    col()
        .key(key)
        .grow(1.0)
        .min_w(0.0)
        .padding(20.0)
        .gap(12.0)
        .radius(12.0)
        .fill(theme.sheet_bg)
        .border(if active || verified { 2.0 } else { 1.0 }, border_c)
        .motion(motion::SNAPPY)
        .child(
            el().size(36.0, 36.0)
                .radius(18.0)
                .center()
                .fill(num_bg)
                .child(text(num).font(theme.t_kiosk_step).color(num_fg)),
        )
        .child(
            text(heading)
                .font(theme.t_kiosk_step)
                .color(theme.ink_primary),
        )
        .child(
            text(body)
                .font(theme.t_body)
                .color(theme.ink_secondary)
                .wrap(),
        )
}
