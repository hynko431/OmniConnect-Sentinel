//! Zero-dependency loopback-only HTTP/1.1 client for `sentinel ui` (`127.0.0.1`).
//! Enforces strict loopback targeting, exact `Host`/`Origin` headers, `sentinel_sid` cookie jar,
//! and `X-Sentinel-CSRF` headers matching `crates/sentinel-cli/src/main.rs`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use rune::AppHandle;

use crate::model::{
    BackendCmd, ConnectionState, KioskStage, ModalState, SentinelState, ShredReceipt,
    StatusResponse, WsResponse,
};

struct RawHttpResponse {
    status: u16,
    set_cookie: Option<String>,
    body: Vec<u8>,
}

struct LocalSession {
    port: u16,
    cookie_sid: Option<String>,
    csrf_token: String,
    backoff_secs: u64,
}

impl LocalSession {
    fn new(port: u16) -> Self {
        Self {
            port,
            cookie_sid: None,
            csrf_token: String::new(),
            backoff_secs: 1,
        }
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        include_csrf: bool,
    ) -> Result<RawHttpResponse, String> {
        let addr: SocketAddr = ([127, 0, 0, 1], self.port).into();
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(900))
            .map_err(|e| format!("connect 127.0.0.1:{}: {e}", self.port))?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(12)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

        let body_bytes = body.unwrap_or(&[]);
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://127.0.0.1:{port}\r\nAccept: application/json\r\nConnection: close\r\n",
            port = self.port
        );
        if let Some(sid) = &self.cookie_sid {
            req.push_str(&format!("Cookie: sentinel_sid={sid}\r\n"));
        }
        if include_csrf && !self.csrf_token.is_empty() {
            req.push_str(&format!("X-Sentinel-CSRF: {}\r\n", self.csrf_token));
        }
        if body.is_some() {
            req.push_str("Content-Type: application/json\r\n");
            req.push_str(&format!("Content-Length: {}\r\n", body_bytes.len()));
        }
        req.push_str("\r\n");

        stream
            .write_all(req.as_bytes())
            .map_err(|e| format!("write headers failed: {e}"))?;
        if !body_bytes.is_empty() {
            stream
                .write_all(body_bytes)
                .map_err(|e| format!("write body failed: {e}"))?;
        }
        let _ = stream.flush();

        let mut raw = Vec::with_capacity(8192);
        stream
            .read_to_end(&mut raw)
            .map_err(|e| format!("read response failed: {e}"))?;
        parse_http_response(&raw)
    }

    fn exchange_bootstrap(&mut self, code: &str) -> Result<(), String> {
        let payload = serde_json::json!({ "bootstrap_token": code.trim() });
        let bytes = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
        let resp = self.request("POST", "/api/v1/session/exchange", Some(&bytes), false)?;
        if resp.status != 200 {
            return Err(format!(
                "Bootstrap exchange rejected (HTTP {})",
                resp.status
            ));
        }
        if let Some(cookie) = resp.set_cookie
            && let Some(sid) = extract_cookie_token(&cookie, "sentinel_sid")
        {
            self.cookie_sid = Some(sid);
        }
        if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&resp.body)
            && let Some(csrf) = val.get("csrf_token").and_then(|v| v.as_str())
        {
            self.csrf_token = csrf.to_owned();
        }
        self.backoff_secs = 1;
        Ok(())
    }

    fn poll_all(&mut self, handle: &AppHandle<SentinelState>) {
        match self.request("GET", "/api/v1/status", None, false) {
            Ok(resp) if resp.status == 401 => {
                self.backoff_secs = (self.backoff_secs * 2).min(16);
                let retry = self.backoff_secs;
                handle.update(move |s, _| {
                    s.connection = ConnectionState::Unauthorized;
                    if matches!(s.modal, ModalState::None) {
                        s.modal = ModalState::SessionAuth;
                    }
                    s.stream_items = vec![crate::model::StreamItem {
                        id: "unauth".into(),
                        title: "AUTHENTICATION REQUIRED".into(),
                        detail: format!(
                            "Enter one-time bootstrap code from `sentinel ui` · Next check in {retry}s"
                        ),
                        badge_text: "HTTP 401".into(),
                        is_alert: true,
                    }];
                });
            }
            Ok(resp) if resp.status == 200 => {
                match serde_json::from_slice::<StatusResponse>(&resp.body) {
                    Ok(status_data) => {
                        if !status_data.csrf_token.is_empty() {
                            self.csrf_token = status_data.csrf_token.clone();
                        }
                        let ws_events = self
                            .request("GET", "/api/v1/ws", None, false)
                            .ok()
                            .filter(|r| r.status == 200)
                            .and_then(|r| serde_json::from_slice::<WsResponse>(&r.body).ok())
                            .map(|w| w.events)
                            .unwrap_or_default();
                        let metrics_text = self
                            .request("GET", "/api/v1/metrics", None, false)
                            .ok()
                            .filter(|r| r.status == 200)
                            .map(|r| String::from_utf8_lossy(&r.body).into_owned())
                            .unwrap_or_default();
                        self.backoff_secs = 1;
                        handle.update(move |s, _| {
                            s.apply_live_status(status_data, ws_events);
                            if !metrics_text.is_empty() {
                                s.prometheus_metrics = metrics_text;
                            }
                        });
                    }
                    Err(e) => {
                        self.backoff_secs = (self.backoff_secs * 2).min(16);
                        let retry = self.backoff_secs;
                        let msg = format!("Malformed status JSON: {e}");
                        handle.update(move |s, _| s.apply_disconnected(retry, msg));
                    }
                }
            }
            Ok(resp) => {
                self.backoff_secs = (self.backoff_secs * 2).min(16);
                let retry = self.backoff_secs;
                let msg = format!("HTTP {}", resp.status);
                handle.update(move |s, _| s.apply_disconnected(retry, msg));
            }
            Err(err) => {
                self.backoff_secs = (self.backoff_secs * 2).min(16);
                let retry = self.backoff_secs;
                handle.update(move |s, _| s.apply_disconnected(retry, err));
            }
        }
    }

    fn execute_scan(&mut self, handle: &AppHandle<SentinelState>, is_kiosk: bool) {
        let body = br#"{"max_files":500}"#;
        match self.request("POST", "/api/v1/scan", Some(body), true) {
            Ok(resp) if resp.status == 200 => {
                let val = serde_json::from_slice::<serde_json::Value>(&resp.body).ok();
                let complete = val
                    .as_ref()
                    .and_then(|v| v.get("complete"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let files = val
                    .as_ref()
                    .and_then(|v| v.get("files_scanned"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let threats = val
                    .as_ref()
                    .and_then(|v| v.get("threats"))
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                handle.update(move |s, _| {
                    s.busy_scan = false;
                    if is_kiosk {
                        s.kiosk_stage = if complete && threats == 0 {
                            KioskStage::VerifiedClean
                        } else {
                            KioskStage::BlockedError
                        };
                        s.kiosk_summary = if complete && threats == 0 {
                            format!(
                                "Live scan complete: {files} files inspected, 0 threats detected. Signed ledger entry recorded."
                            )
                        } else if threats > 0 {
                            format!(
                                "THREAT BLOCKED ({threats} threats across {files} files) — transfer halted fail-closed."
                            )
                        } else {
                            format!(
                                "Scan incomplete ({files} files inspected, {threats} threats) — volume remains held offline fail-closed."
                            )
                        };
                    }
                });
                self.poll_all(handle);
            }
            Ok(resp) => {
                let code = resp.status;
                handle.update(move |s, _| {
                    s.busy_scan = false;
                    if is_kiosk {
                        s.kiosk_stage = KioskStage::BlockedError;
                        s.kiosk_summary = format!("Kiosk scan rejected by agent (HTTP {code}).");
                    }
                });
            }
            Err(e) => {
                handle.update(move |s, _| {
                    s.busy_scan = false;
                    if is_kiosk {
                        s.kiosk_stage = KioskStage::BlockedError;
                        s.kiosk_summary = format!("Agent unreachable: {e}");
                    }
                });
            }
        }
    }

    fn execute_shred(&mut self, handle: &AppHandle<SentinelState>) {
        let body = br#"{"create_ephemeral_canary":true}"#;
        match self.request("POST", "/api/v1/shred", Some(body), true) {
            Ok(resp) if resp.status == 200 => {
                match serde_json::from_slice::<ShredReceipt>(&resp.body) {
                    Ok(receipt) => {
                        handle.update(move |s, _| {
                            s.busy_shred = false;
                            s.apply_shred_receipt(receipt);
                        });
                        self.poll_all(handle);
                    }
                    Err(e) => {
                        let msg = format!("Shred receipt decode error: {e}");
                        handle.update(move |s, _| {
                            s.busy_shred = false;
                            s.shred_status_is_error = true;
                            s.shred_status_msg = msg;
                        });
                    }
                }
            }
            Ok(resp) => {
                let msg = format!("Shred failed (HTTP {})", resp.status);
                handle.update(move |s, _| {
                    s.busy_shred = false;
                    s.shred_status_is_error = true;
                    s.shred_status_msg = msg;
                });
            }
            Err(e) => {
                handle.update(move |s, _| {
                    s.busy_shred = false;
                    s.shred_status_is_error = true;
                    s.shred_status_msg = format!("Agent unreachable: {e}");
                });
            }
        }
    }
}

/// Spawns the background localhost polling & action worker thread.
pub fn spawn_backend_worker(
    port: u16,
    initial_bootstrap: Option<String>,
    rx: Receiver<BackendCmd>,
    handle: AppHandle<SentinelState>,
) {
    std::thread::Builder::new()
        .name("sentinel-ui-api".into())
        .spawn(move || {
            let mut session = LocalSession::new(port);
            if let Some(code) = initial_bootstrap
                && !code.trim().is_empty()
                && let Err(err) = session.exchange_bootstrap(&code)
            {
                handle.update(move |s, _| {
                    s.auth_error = Some(err);
                    s.modal = ModalState::SessionAuth;
                });
            }
            session.poll_all(&handle);

            let mut next_poll = Instant::now() + Duration::from_secs(session.backoff_secs.max(3));
            loop {
                let wait = next_poll
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(500));
                match rx.recv_timeout(wait) {
                    Ok(BackendCmd::PollNow) => {
                        session.poll_all(&handle);
                        next_poll =
                            Instant::now() + Duration::from_secs(session.backoff_secs.max(3));
                    }
                    Ok(BackendCmd::ExchangeBootstrap(code)) => {
                        match session.exchange_bootstrap(&code) {
                            Ok(()) => {
                                handle.update(|s, _| {
                                    s.auth_error = None;
                                    s.bootstrap_input = rune::TextEdit::new("");
                                    s.modal = ModalState::None;
                                });
                                session.poll_all(&handle);
                            }
                            Err(err) => {
                                handle.update(move |s, _| {
                                    s.auth_error = Some(err);
                                });
                            }
                        }
                        next_poll =
                            Instant::now() + Duration::from_secs(session.backoff_secs.max(3));
                    }
                    Ok(BackendCmd::TriggerScan) => {
                        session.execute_scan(&handle, false);
                        next_poll = Instant::now() + Duration::from_secs(3);
                    }
                    Ok(BackendCmd::TriggerKioskScan) => {
                        session.execute_scan(&handle, true);
                        next_poll = Instant::now() + Duration::from_secs(3);
                    }
                    Ok(BackendCmd::TriggerShred) => {
                        session.execute_shred(&handle);
                        next_poll = Instant::now() + Duration::from_secs(3);
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        if Instant::now() >= next_poll {
                            session.poll_all(&handle);
                            let interval = if session.backoff_secs > 1 {
                                session.backoff_secs
                            } else {
                                4
                            };
                            next_poll = Instant::now() + Duration::from_secs(interval);
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        })
        .ok();
}

fn parse_http_response(raw: &[u8]) -> Result<RawHttpResponse, String> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "Incomplete HTTP response".to_owned())?;
    let head = String::from_utf8_lossy(&raw[..sep]);
    let mut lines = head.lines();
    let status_line = lines.next().ok_or_else(|| "Empty HTTP status line".to_owned())?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("Invalid HTTP status line: {status_line}"))?;

    let mut set_cookie = None;
    let mut is_chunked = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k_lower = k.trim().to_ascii_lowercase();
            if k_lower == "set-cookie" {
                set_cookie = Some(v.trim().to_owned());
            } else if k_lower == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked") {
                is_chunked = true;
            }
        }
    }

    let body_slice = &raw[sep + 4..];
    let body = if is_chunked {
        decode_chunked(body_slice)
    } else {
        body_slice.to_vec()
    };

    Ok(RawHttpResponse {
        status,
        set_cookie,
        body,
    })
}

fn decode_chunked(mut src: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(pos) = src.windows(2).position(|w| w == b"\r\n") {
        let len_str = String::from_utf8_lossy(&src[..pos]);
        let hex_part = len_str.split(';').next().unwrap_or("").trim();
        let Ok(len) = usize::from_str_radix(hex_part, 16) else {
            break;
        };
        if len == 0 {
            break;
        }
        src = &src[pos + 2..];
        if src.len() < len {
            out.extend_from_slice(src);
            break;
        }
        out.extend_from_slice(&src[..len]);
        src = &src[len..];
        if src.starts_with(b"\r\n") {
            src = &src[2..];
        }
    }
    out
}

fn extract_cookie_token(header_val: &str, name: &str) -> Option<String> {
    for part in header_val.split(';') {
        if let Some((k, v)) = part.trim().split_once('=')
            && k.trim() == name
        {
            return Some(v.trim().to_owned());
        }
    }
    None
}
