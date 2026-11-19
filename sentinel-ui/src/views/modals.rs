//! Accessible Rune modal dialogs (`rune_kit::Dialog`):
//! 1. MITRE ATT&CK® Ring 3 Technical Inspector
//! 2. Deep CDR & Prometheus Telemetry Inspector
//! 3. Confirm NIST SP 800-88 Clear (Logical) Destructive Confirmation
//! 4. Session Bootstrap Authentication Prompt

use rune::{El, col, row, spacer, text};
use rune_kit::{Button, ButtonVariant, ControlSize, Dialog, TextInput};

use crate::model::{BackendCmd, ModalState, SentinelState, find_mitre};
use crate::theme::SentinelTheme;
use crate::views::status_pill;

pub fn build_modals(s: &SentinelState, theme: &SentinelTheme, layer: &mut Vec<El>) {
    match &s.modal {
        ModalState::None => {}
        ModalState::Mitre(id) => build_mitre_modal(id, theme, layer),
        ModalState::CdrTelemetry => build_cdr_telemetry_modal(s, theme, layer),
        ModalState::ShredConfirm => build_shred_confirm_modal(theme, layer),
        ModalState::SessionAuth => build_session_auth_modal(s, theme, layer),
    }
}

fn build_mitre_modal(technique_id: &'static str, theme: &SentinelTheme, layer: &mut Vec<El>) {
    let info = find_mitre(technique_id);

    let body = col()
        .w_full()
        .px(16.0)
        .pb(16.0)
        .gap(12.0)
        .child(
            row()
                .gap(8.0)
                .center_y()
                .child(status_pill(
                    theme,
                    info.id,
                    theme.info_fg,
                    theme.info_bg,
                    theme.info_border,
                ))
                .child(status_pill(
                    theme,
                    format!("✓ {}", info.status),
                    theme.safe_fg,
                    theme.safe_bg,
                    theme.safe_border,
                )),
        )
        .child(detail_block(theme, "Threat Description", info.threat_desc))
        .child(detail_block(
            theme,
            "Ring 3 Architectural Mitigation",
            info.mitigation,
        ))
        .child(detail_block(theme, "Compliance Mapping", info.compliance))
        .child(
            row()
                .w_full()
                .pt(4.0)
                .child(spacer())
                .child(
                    Button::new("Close")
                        .variant(ButtonVariant::Contrast)
                        .control_size(ControlSize::Large)
                        .on_press(|s: &mut SentinelState| s.modal = ModalState::None)
                        .build(&theme.kit)
                        .key("btn-close-mitre"),
                ),
        );

    Dialog::new("mitre", info.full_title)
        .description("MITRE ATT&CK® Peripheral Defense Technical Inspector")
        .open(true)
        .width(540.0)
        .fit()
        .on_close(|s: &mut SentinelState| s.modal = ModalState::None)
        .child(body)
        .build(&theme.kit, layer);
}

fn build_cdr_telemetry_modal(s: &SentinelState, theme: &SentinelTheme, layer: &mut Vec<El>) {
    let left_summary = format!(
        "Agent Status: {} ({})\nPosture Compliant: {}\nQuarantine Vault (.quar): {}\nLast Scan Complete: {}\nMDM Policy: {} (v{})\nZero-Trust USB: {} · Block HID+Storage: {} · Require CDR: {}",
        s.status_label,
        s.architecture_label,
        s.posture.is_compliant,
        s.quarantine_count,
        s.last_scan_complete,
        if s.mdm_policy.policy_id.is_empty() {
            "NONE"
        } else {
            &s.mdm_policy.policy_id
        },
        s.mdm_policy.version,
        s.mdm_policy.enforce_usb_zero_trust,
        s.mdm_policy.block_composite_hid_storage,
        s.mdm_policy.require_cdr_for_documents
    );

    let right_summary = format!(
        "Active CDR Workers: {}\nWorker Processed Total: {}\nTotal Rebuilt (CDR): {}\nCumulative CDR Time: {} ms\nAudit Ledger Verified: {}",
        s.workers.active,
        s.workers.processed_total,
        s.files_cleaned,
        s.workers.duration_ms_total,
        s.audit_ledger_verified
    );

    let prom_preview = if s.prometheus_metrics.is_empty() {
        "No live /api/v1/metrics scrape loaded yet.".to_owned()
    } else {
        s.prometheus_metrics
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .take(8)
            .collect::<Vec<_>>()
            .join("\n")
    };

    let body = col()
        .w_full()
        .px(16.0)
        .pb(16.0)
        .gap(12.0)
        .child(
            row()
                .w_full()
                .gap(12.0)
                .child(code_pane(
                    theme,
                    "Posture & Quarantine State",
                    &left_summary,
                    theme.danger_fg,
                ))
                .child(code_pane(
                    theme,
                    "Sanitized CDR & Ledger State",
                    &right_summary,
                    theme.safe_fg,
                )),
        )
        .child(code_pane(
            theme,
            "Prometheus SLI Snapshot (GET /api/v1/metrics)",
            &prom_preview,
            theme.info_fg,
        ))
        .child(
            row()
                .w_full()
                .pt(4.0)
                .child(spacer())
                .child(
                    Button::new("Close")
                        .variant(ButtonVariant::Contrast)
                        .control_size(ControlSize::Large)
                        .on_press(|s: &mut SentinelState| s.modal = ModalState::None)
                        .build(&theme.kit)
                        .key("btn-close-cdr-modal"),
                ),
        );

    Dialog::new("cdr-telemetry", "Deep CDR & Prometheus Telemetry Inspector")
        .description("Live inspection of backend posture, quarantine count, worker SLIs, and ledger integrity")
        .open(true)
        .width(640.0)
        .fit()
        .on_close(|s: &mut SentinelState| s.modal = ModalState::None)
        .child(body)
        .build(&theme.kit, layer);
}

fn build_shred_confirm_modal(theme: &SentinelTheme, layer: &mut Vec<El>) {
    let body = col()
        .w_full()
        .px(16.0)
        .pb(16.0)
        .gap(12.0)
        .child(
            text("Execute an irreversible 3-pass write-through logical clear (0x00, 0xFF, CSPRNG) with read-back SHA-256 verification and 3-cycle filename scrambling on an ephemeral staging canary?")
                .font(theme.t_body)
                .color(theme.ink_primary)
                .wrap(),
        )
        .child(
            text("Media Honesty: On wear-leveled flash/SSD media, file-level overwrites are strictly classified as NIST SP 800-88 Clear (logical), never physical Purge.")
                .font(theme.t_caption)
                .color(theme.ink_secondary)
                .wrap(),
        )
        .child(
            row()
                .w_full()
                .pt(6.0)
                .gap(10.0)
                .child(spacer())
                .child(
                    Button::new("Cancel")
                        .variant(ButtonVariant::Outline)
                        .control_size(ControlSize::Large)
                        .on_press(|s: &mut SentinelState| s.modal = ModalState::None)
                        .build(&theme.kit)
                        .key("btn-cancel-shred"),
                )
                .child(
                    Button::new("Confirm & Execute Clear")
                        .variant(ButtonVariant::Danger)
                        .control_size(ControlSize::Large)
                        .on_press(|s: &mut SentinelState| {
                            s.modal = ModalState::None;
                            s.busy_shred = true;
                            s.shred_status_is_error = false;
                            s.shred_status_msg =
                                "Executing POST /api/v1/shred (3-pass write-through)...".into();
                            s.send_cmd(BackendCmd::TriggerShred);
                        })
                        .build(&theme.kit)
                        .key("btn-confirm-shred"),
                ),
        );

    Dialog::new("shred-confirm", "Confirm NIST SP 800-88 Clear (Logical)")
        .description("Irreversible 3-pass staging canary sanitization with CSRF verification")
        .open(true)
        .width(500.0)
        .fit()
        .on_close(|s: &mut SentinelState| s.modal = ModalState::None)
        .child(body)
        .build(&theme.kit, layer);
}

fn build_session_auth_modal(s: &SentinelState, theme: &SentinelTheme, layer: &mut Vec<El>) {
    let input = TextInput::new(&s.bootstrap_input)
        .label("One-time bootstrap code")
        .placeholder("Paste bootstrap code from `sentinel ui`...")
        .width(None)
        .large()
        .on_edit(|s: &mut SentinelState| &mut s.bootstrap_input)
        .on_submit(|s: &mut SentinelState, _| {
            let code = s.bootstrap_input.text.trim().to_owned();
            if !code.is_empty() {
                s.send_cmd(BackendCmd::ExchangeBootstrap(code));
            }
        })
        .build(&theme.kit)
        .key("input-bootstrap-code");

    let mut content = col()
        .w_full()
        .px(16.0)
        .pb(16.0)
        .gap(12.0)
        .child(
            text(format!(
                "Target: http://127.0.0.1:{} — Launch `sentinel ui --port {}` and paste the one-time bootstrap code to exchange for an HttpOnly session cookie + CSRF token.",
                s.port, s.port
            ))
            .font(theme.t_body)
            .color(theme.ink_secondary)
            .wrap(),
        )
        .child(input);

    if let Some(err) = &s.auth_error {
        content = content.child(
            text(format!("Authentication Error: {err}"))
                .font(theme.t_caption)
                .color(theme.danger_fg)
                .wrap(),
        );
    }

    content = content.child(
        row()
            .w_full()
            .pt(4.0)
            .gap(10.0)
            .child(spacer())
            .child(
                Button::new("Cancel")
                    .variant(ButtonVariant::Outline)
                    .control_size(ControlSize::Large)
                    .on_press(|s: &mut SentinelState| s.modal = ModalState::None)
                    .build(&theme.kit)
                    .key("btn-cancel-auth"),
            )
            .child(
                Button::new("Authenticate")
                    .variant(ButtonVariant::Contrast)
                    .control_size(ControlSize::Large)
                    .on_press(|s: &mut SentinelState| {
                        let code = s.bootstrap_input.text.trim().to_owned();
                        if !code.is_empty() {
                            s.send_cmd(BackendCmd::ExchangeBootstrap(code));
                        }
                    })
                    .build(&theme.kit)
                    .key("btn-submit-auth"),
            ),
    );

    Dialog::new("session-auth", "Session Bootstrap Authentication")
        .description("Constant-time loopback session exchange (POST /api/v1/session/exchange)")
        .open(true)
        .width(500.0)
        .fit()
        .on_close(|s: &mut SentinelState| s.modal = ModalState::None)
        .child(content)
        .build(&theme.kit, layer);
}

fn detail_block(theme: &SentinelTheme, heading: &str, body: &str) -> El {
    col()
        .w_full()
        .padding(10.0)
        .gap(4.0)
        .radius(6.0)
        .fill(theme.subtle_bg)
        .border(1.0, theme.border_hairline)
        .child(text(heading).font(theme.t_label).color(theme.ink_primary))
        .child(text(body).font(theme.t_body).color(theme.ink_secondary).wrap())
}

fn code_pane(theme: &SentinelTheme, title: &str, body: &str, accent: rune::Color) -> El {
    col()
        .grow(1.0)
        .min_w(0.0)
        .padding(10.0)
        .gap(6.0)
        .radius(6.0)
        .fill(theme.subtle_bg)
        .border(1.0, theme.border_hairline)
        .child(text(title).font(theme.t_label).color(accent))
        .child(
            text(body)
                .font(theme.t_mono)
                .color(theme.ink_primary)
                .wrap(),
        )
}
