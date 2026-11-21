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

#![forbid(unsafe_code)]

mod client;
mod model;
mod schematic;
mod theme;
mod views;

use std::path::Path;
use std::sync::mpsc;
use std::time::{SystemTime, UNIX_EPOCH};

use rune::{App, AppSpec, Key, KeyEvent, Tx};

use crate::model::{ModalState, PersonaMode, SentinelState, ThemeMode};

struct LaunchOpts {
    port: u16,
    bootstrap: Option<String>,
    demo: bool,
    rune_args: Vec<String>,
    is_headless: bool,
}

/// Maximum permitted size (bytes) for a one-time bootstrap handoff file (`CSE-22`).
const MAX_BOOTSTRAP_HANDOFF_BYTES: u64 = 4096;

/// Verifies that neither `path` nor any existing ancestor component is a symlink or NTFS reparse point.
fn is_symlink_or_reparse_metadata(meta: &std::fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return true;
        }
    }
    false
}

/// Reads and immediately overwrites + deletes a one-time bootstrap handoff JSON file written
/// by `sentinel ui --native` (`CSE-22`), rejecting symlinks/reparse points and oversized files,
/// reading strictly via a no-follow handle, and enforcing the embedded `expires_unix` 30-second TTL.
fn consume_bootstrap_handoff_file(path: &Path) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom, Write};

    // Reject symlink/reparse ancestors and leaf BEFORE opening
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            break;
        }
        if let Ok(meta) = std::fs::symlink_metadata(ancestor)
            && is_symlink_or_reparse_metadata(&meta)
        {
            return None;
        }
    }

    let lmeta = std::fs::symlink_metadata(path).ok()?;
    if is_symlink_or_reparse_metadata(&lmeta)
        || !lmeta.is_file()
        || lmeta.len() > MAX_BOOTSTRAP_HANDOFF_BYTES
    {
        return None;
    }

    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        #[cfg(target_arch = "aarch64")]
        const O_NOFOLLOW: i32 = 0o100000;
        #[cfg(not(target_arch = "aarch64"))]
        const O_NOFOLLOW: i32 = 0o400000;
        opts.custom_flags(O_NOFOLLOW);
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        const O_NOFOLLOW: i32 = 0x0100;
        opts.custom_flags(O_NOFOLLOW);
    }

    let mut file = opts.open(path).ok()?;
    let fmeta = file.metadata().ok()?;
    if is_symlink_or_reparse_metadata(&fmeta)
        || !fmeta.is_file()
        || fmeta.len() > MAX_BOOTSTRAP_HANDOFF_BYTES
    {
        return None;
    }

    let mut bytes = Vec::with_capacity(fmeta.len().min(MAX_BOOTSTRAP_HANDOFF_BYTES) as usize);
    let read_ok = (&file)
        .take(MAX_BOOTSTRAP_HANDOFF_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_ok();

    // Immediately overwrite and truncate through the verified open handle, then unlink (one-time use)
    let wipe_len = (fmeta.len() as usize).clamp(64, MAX_BOOTSTRAP_HANDOFF_BYTES as usize);
    let zeros = vec![0u8; wipe_len];
    let _ = file.seek(SeekFrom::Start(0));
    let _ = file.write_all(&zeros);
    let _ = file.set_len(0);
    let _ = file.sync_all();
    drop(file);
    let _ = std::fs::remove_file(path);

    if !read_ok || (bytes.len() as u64) > MAX_BOOTSTRAP_HANDOFF_BYTES {
        return None;
    }

    let parsed: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    let expires_unix = parsed.get("expires_unix")?.as_i64()?;
    if now_unix > expires_unix {
        return None;
    }
    parsed
        .get("bootstrap_token")?
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
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
            "--bootstrap-file" => {
                if let Some(val) = raw.get(i + 1) {
                    bootstrap = consume_bootstrap_handoff_file(Path::new(val));
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

    #[test]
    fn t50_consume_bootstrap_handoff_file_reads_once_deletes_and_enforces_ttl() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_secs() as i64;
        let tmp = std::env::temp_dir().join(format!("sentinel_ui_t50_{now}.json"));
        let valid_payload = serde_json::json!({
            "bootstrap_token": "boot_handoff_valid_1234",
            "expires_unix": now + 30
        })
        .to_string();
        std::fs::write(&tmp, valid_payload).expect("write valid handoff");

        let consumed = consume_bootstrap_handoff_file(&tmp);
        assert_eq!(consumed.as_deref(), Some("boot_handoff_valid_1234"));
        assert!(
            !tmp.exists(),
            "Handoff file must be deleted immediately after reading"
        );

        let expired_path = std::env::temp_dir().join(format!("sentinel_ui_t50_exp_{now}.json"));
        let expired_payload = serde_json::json!({
            "bootstrap_token": "boot_handoff_expired_9999",
            "expires_unix": now - 5
        })
        .to_string();
        std::fs::write(&expired_path, expired_payload).expect("write expired handoff");
        assert_eq!(consume_bootstrap_handoff_file(&expired_path), None);
        assert!(
            !expired_path.exists(),
            "Expired handoff file must still be deleted immediately"
        );

        // Oversized (> 4096 bytes) handoff file must be rejected without consuming
        let oversized_path = std::env::temp_dir().join(format!("sentinel_ui_t50_big_{now}.json"));
        std::fs::write(&oversized_path, vec![b'A'; 5000]).expect("write oversized");
        assert_eq!(consume_bootstrap_handoff_file(&oversized_path), None);
        let _ = std::fs::remove_file(&oversized_path);
    }
}
