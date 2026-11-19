# OmniConnect Sentinel — Native Rune GPU UI (`sentinel-ui`)

A standalone, native GPU-rendered Cyber Defense Station & Air-Gapped Kiosk desktop application for **OmniConnect Sentinel**, built with the **[Rune Framework](https://github.com/anomalyco/rune)** (`wgpu` + `Taffy` + `Parley` + `AccessKit` + `rune-kit`).

> **Workspace Supply-Chain Isolation:** `sentinel-ui` is explicitly excluded from the root Cargo workspace (`exclude = ["sentinel-ui"]` in `../Cargo.toml`) so the core security workspace's strict `cargo deny` (`allow-git = []`), `cargo audit`, and zero-suppression CI gates remain 100% untouched.

---

## Key Enhancements Over the Browser Dashboard

1. **Native GPU Rendering (`wgpu`) & Analytic Spring Motion:** Runs at display refresh rate (60–120 Hz) with zero browser runtime, zero DOM/XSS surface, and Rune's premultiplied OKLab color transitions + spring-animated controls.
2. **True GPU Vector USB Bus Schematic (`src/schematic.rs`):** Renders the 4-conductor USB bus (`VBUS`, `D-`, `D+`, `GND`) with `rune::shape::Shape` antialiased GPU strokes and honest labeling (`Software Pre-Mount Hold (I1)` — removing misleading physical copper-cut warranties and fabricated electrical voltage/amperage readings).
3. **Live 6-Check Hardware Posture Matrix:** Surfaces all 6 `PostureReport` checks (`AutoMount Off`, `Volumes Offline`, `User Deny Policy`, `Install Restrict`, `Write Protect`, `Overall Compliant`) alongside interactive MITRE ATT&CK® defense inspector cards (`T1091`, `T1052`, `T1200`, `T1025`).
4. **Loopback-Only Zero-Dependency API Client (`src/client.rs`):** Communicates strictly with `127.0.0.1:<port>` on a background worker thread (`AppHandle::update`) using exact `Host`/`Origin` validation, `POST /api/v1/session/exchange` (`HttpOnly` `sentinel_sid` cookie jar), `X-Sentinel-CSRF` headers, and exponential backoff (`1s` → `16s`).
5. **Zero-Fabrication Disconnected State (`T23`) & Fail-Closed Kiosk Gate:** Displays explicit `DISCONNECTED — NO LIVE DATA` with zero fake counters when offline, and gates Kiosk Step 3 strictly on `complete == true && threats == 0`.
6. **Dual Theme (Framed Light / Cyber Ops Dark) & Dual Persona (`SOC Analyst HUD` / `Air-Gapped Kiosk`)** with AccessKit accessibility roles and keyboard-trapped `rune_kit::Dialog` modals.
7. **Deterministic Headless Verification:** Captures pixel-exact PNG snapshots and AccessKit element trees from CI or coding agents without needing a display server.

---

## Running `sentinel-ui`

### 1. Live Mode (Connected to Local `sentinel ui`)
Start the backend in one terminal:
```bash
cargo run -p sentinel-cli -- ui --port 8088 --no-browser
```
Copy the printed one-time bootstrap code and launch the native Rune UI:
```bash
cd sentinel-ui
cargo run -- --port 8088 --bootstrap <ONE_TIME_BOOTSTRAP_CODE>
```
*(Or launch without `--bootstrap` and click **Session Auth** inside the header to paste it interactively.)*

### 2. Watermarked Demo Preview Mode
```bash
cd sentinel-ui
cargo run -- --demo
```

### 3. Headless PNG Snapshots & AccessKit Tree Verification
```bash
cd sentinel-ui
cargo run -- --snap soc-demo-light.png --scene demo-light --size 1400x920
cargo run -- --snap soc-demo-dark.png --scene demo-dark --size 1400x920
cargo run -- --snap kiosk-demo.png --scene kiosk-demo --size 1400x920
cargo run -- --snap mitre-modal.png --scene mitre-modal --size 1400x920
cargo run -- --snap disconnected.png --scene disconnected --size 1400x920
cargo run -- --tree tree.json --scene demo-light --size 1400x920
```

### 4. Headless Interactive Runtime Tests
```bash
cd sentinel-ui
cargo test
```
