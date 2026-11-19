//! OmniConnect Sentinel — Native GPU-Rendered Cyber Defense Station & Kiosk UI
//! Built with the Rune Framework (`anomalyco/rune` + `rune-kit`).
//!
//! Run interactively:
//!   `cargo run -- --port 8088 --bootstrap <ONE_TIME_TOKEN>`
//!   `cargo run -- --demo`
//!
//! Run headlessly to capture deterministic PNG screenshots & AccessKit element trees:
//!   `cargo run -- --snap soc-demo-light.png --scene demo-light --size 1400x920`
//!   `cargo run -- --snap soc-demo-dark.png --scene demo-dark --size 1400x920`
//!   `cargo run -- --snap kiosk-demo.png --scene kiosk-demo --size 1400x920`
//!   `cargo run -- --snap mitre-modal.png --scene mitre-modal --size 1400x920`
//!   `cargo run -- --snap disconnected.png --scene disconnected --size 1400x920`

mod client;
mod model;
mod schematic;
mod theme;
mod views;

use std::sync::mpsc;

use rune::{App, AppSpec, Key, KeyEvent, Tx};

use crate::model::{ModalState, PersonaMode, SentinelState, ThemeMode};

struct LaunchOpts {
    port: u16,
    bootstrap: Option<String>,
    demo: bool,
    rune_args: Vec<String>,
    is_headless: bool,
}

fn parse_launch_opts() -> LaunchOpts {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut port = 8088u16;
    let mut bootstrap = None;
    let mut demo = false;
    let mut rune_args = Vec::new();
    let mut is_headless = false;

    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--port" => {
                if let Some(val) = raw.get(i + 1).and_then(|s| s.parse::<u16>().ok()) {
                    port = val;
                    i += 2;
                    continue;
                }
            }
            "--bootstrap" => {
                if let Some(val) = raw.get(i + 1) {
                    bootstrap = Some(val.clone());
                    i += 2;
                    continue;
                }
            }
            "--demo" => {
                demo = true;
                i += 1;
                continue;
            }
            flag => {
                if matches!(
                    flag,
                    "--snap" | "--tree" | "--script" | "--trace" | "--strip" | "--video" | "--html"
                ) {
                    is_headless = true;
                }
                rune_args.push(raw[i].clone());
            }
        }
        i += 1;
    }

    LaunchOpts {
        port,
        bootstrap,
        demo,
        rune_args,
        is_headless,
    }
}

fn handle_window_key(s: &mut SentinelState, ev: &KeyEvent, _tx: &mut Tx) -> bool {
    if matches!(ev.key, Key::Escape) && !matches!(s.modal, ModalState::None) {
        s.modal = ModalState::None;
        return true;
    }
    false
}

fn main() {
    let opts = parse_launch_opts();
    let (tx, rx) = mpsc::channel();
    let port = opts.port;
    let demo = opts.demo;
    let headless = opts.is_headless;

    let spec = AppSpec::<SentinelState> {
        min_size: Some((1024.0, 680.0)),
        on_key: Some(handle_window_key),
        scenes: &[
            ("disconnected", |s| {
                s.apply_disconnected(4, "Connection refused (no local agent running)");
            }),
            ("demo-light", |s| {
                s.theme = ThemeMode::Light;
                s.persona = PersonaMode::SocHud;
                s.apply_watermarked_demo();
            }),
            ("demo-dark", |s| {
                s.theme = ThemeMode::Dark;
                s.persona = PersonaMode::SocHud;
                s.apply_watermarked_demo();
            }),
            ("kiosk-demo", |s| {
                s.theme = ThemeMode::Light;
                s.persona = PersonaMode::Kiosk;
                s.apply_watermarked_demo();
            }),
            ("mitre-modal", |s| {
                s.theme = ThemeMode::Dark;
                s.persona = PersonaMode::SocHud;
                s.apply_watermarked_demo();
                s.modal = ModalState::Mitre("T1091");
            }),
            ("shred-modal", |s| {
                s.theme = ThemeMode::Light;
                s.persona = PersonaMode::SocHud;
                s.apply_watermarked_demo();
                s.modal = ModalState::ShredConfirm;
            }),
        ],
        ..AppSpec::new(
            "OmniConnect Sentinel — Native Rune Defense Station",
            (1400.0, 920.0),
            SentinelState::default,
            views::view,
        )
    };

    let cmd_tx = if headless || demo { None } else { Some(tx) };
    let app = App::new(spec)
        .args(opts.rune_args)
        .init(move || {
            let mut state = SentinelState::new(port, cmd_tx);
            if demo {
                state.apply_watermarked_demo();
            }
            state
        });

    if !headless && !demo {
        let handle = app.handle();
        client::spawn_backend_worker(port, opts.bootstrap, rx, handle);
    }

    app.run();
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune::{Env, Mods, Runtime};

    fn make_runtime(demo: bool) -> Runtime<SentinelState> {
        let mut state = SentinelState::new(8088, None);
        if demo {
            state.apply_watermarked_demo();
        } else {
            state.apply_disconnected(2, "Offline test");
        }
        let mut rt = Runtime::new(state, views::view, (1400.0, 920.0), Env::new(false, 1.0));
        rt.on_key = Some(handle_window_key);
        rt.frame(0.0);
        rt
    }

    #[test]
    fn t23_disconnected_state_never_fabricates_telemetry() {
        let rt = make_runtime(false);
        assert_eq!(rt.state.files_cleaned, 0);
        assert_eq!(rt.state.quarantine_count, 0);
        assert!(!rt.state.audit_ledger_verified);
        let (_, _, _, vol) = rt.state.bus_telemetry_readout();
        assert_eq!(vol, "DISCONNECTED — NO LIVE DATA");
        assert!(rt.find("system-health-pill").is_some());
    }

    #[test]
    fn clicking_mitre_chip_opens_inspector_modal_and_escape_dismisses() {
        let mut rt = make_runtime(true);
        let (x, y) = rt.find("mitre-chip-T1091").expect("MITRE chip must exist");
        rt.pointer_down(x, y);
        rt.pointer_up(x, y);
        rt.frame(1.0 / 60.0);
        assert_eq!(rt.state.modal, ModalState::Mitre("T1091"));

        rt.key(KeyEvent {
            key: Key::Escape,
            mods: Mods::default(),
        });
        rt.frame(1.0 / 60.0);
        assert_eq!(rt.state.modal, ModalState::None);
    }

    #[test]
    fn clicking_theme_and_shred_buttons_updates_state_cleanly() {
        let mut rt = make_runtime(true);
        assert_eq!(rt.state.theme, ThemeMode::Light);

        let (tx, ty) = rt.find("btn-theme-toggle").expect("theme toggle must exist");
        rt.pointer_down(tx, ty);
        rt.pointer_up(tx, ty);
        rt.frame(1.0 / 60.0);
        assert_eq!(rt.state.theme, ThemeMode::Dark);

        let (sx, sy) = rt
            .find("btn-initiate-shred")
            .expect("shred trigger must exist");
        rt.pointer_down(sx, sy);
        rt.pointer_up(sx, sy);
        rt.frame(1.0 / 60.0);
        assert_eq!(rt.state.modal, ModalState::ShredConfirm);
    }

    #[test]
    fn toggling_bus_hold_switch_flips_interlock_preview() {
        let mut rt = make_runtime(true);
        assert!(rt.state.bus_hold_active);
        let (x, y) = rt
            .find("switch-bus-hold")
            .expect("bus hold switch must exist");
        rt.pointer_down(x, y);
        rt.pointer_up(x, y);
        rt.frame(1.0 / 60.0);
        assert!(!rt.state.bus_hold_active);
    }
}
