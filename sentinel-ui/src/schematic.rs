//! Native GPU-rendered vector schematic (`rune::shape::Shape`) illustrating OmniConnect
//! Sentinel's 4-conductor USB bus and software MountMgr/Ring-3 logical data interlock.

use rune::shape::{LineCap, Shape};
use rune::{Color, El, canvas, col, el, row, text};

use crate::theme::SentinelTheme;

/// Draws an antialiased GPU vector schematic of the USB bus & logical data gate.
/// Honestly distinguishes physical power traces (VBUS/GND) from software-gated D-/D+ data paths.
pub fn usb_bus_schematic(theme: &SentinelTheme, bus_hold_active: bool) -> El {
    let grid_c = theme.border_hairline;
    let vbus_c = theme.info_fg;
    let gnd_c = theme.ink_muted;
    let data_left_c = if bus_hold_active {
        theme.danger_fg
    } else {
        theme.info_fg
    };
    let data_right_c = if bus_hold_active {
        theme.border_strong
    } else {
        theme.info_fg
    };

    let mut s = Shape::new().view_box(600.0, 126.0);

    // Subtle schematic guide rails
    for y in [22.0_f32, 50.0, 78.0, 106.0] {
        s = s.line([20.0, y], [580.0, y], 1.0, LineCap::Butt, grid_c);
    }

    // Vertical gate boundary markers
    s = s.line([248.0, 10.0], [248.0, 118.0], 1.0, LineCap::Butt, grid_c);
    s = s.line([352.0, 10.0], [352.0, 118.0], 1.0, LineCap::Butt, grid_c);

    // Pin 1: VBUS (+5.0V Power — continuous)
    s = s.line([24.0, 22.0], [576.0, 22.0], 3.2, LineCap::Round, vbus_c);
    s = draw_node_pad(s, [24.0, 22.0], 4.5, vbus_c);
    s = draw_node_pad(s, [576.0, 22.0], 4.5, vbus_c);

    // Pin 2: D- (Negative Data — gated by software interlock)
    s = s.line([24.0, 50.0], [260.0, 50.0], 2.8, LineCap::Round, data_left_c);
    s = draw_node_pad(s, [24.0, 50.0], 4.2, data_left_c);
    s = draw_node_pad(s, [260.0, 50.0], 4.2, data_left_c);
    if bus_hold_active {
        // Open switch arm (held offline)
        s = s.line([260.0, 50.0], [322.0, 34.0], 3.0, LineCap::Round, data_left_c);
    } else {
        // Closed bridge (Ring 3 UMDF / ShadowCache filtered)
        s = s.line([260.0, 50.0], [340.0, 50.0], 3.0, LineCap::Round, data_left_c);
    }
    s = draw_node_pad(s, [340.0, 50.0], 4.2, data_right_c);
    s = s.line([340.0, 50.0], [576.0, 50.0], 2.8, LineCap::Round, data_right_c);
    s = draw_node_pad(s, [576.0, 50.0], 4.2, data_right_c);

    // Pin 3: D+ (Positive Data — gated by software interlock)
    s = s.line([24.0, 78.0], [260.0, 78.0], 2.8, LineCap::Round, data_left_c);
    s = draw_node_pad(s, [24.0, 78.0], 4.2, data_left_c);
    s = draw_node_pad(s, [260.0, 78.0], 4.2, data_left_c);
    if bus_hold_active {
        s = s.line([260.0, 78.0], [322.0, 62.0], 3.0, LineCap::Round, data_left_c);
    } else {
        s = s.line([260.0, 78.0], [340.0, 78.0], 3.0, LineCap::Round, data_left_c);
    }
    s = draw_node_pad(s, [340.0, 78.0], 4.2, data_right_c);
    s = s.line([340.0, 78.0], [576.0, 78.0], 2.8, LineCap::Round, data_right_c);
    s = draw_node_pad(s, [576.0, 78.0], 4.2, data_right_c);

    // Pin 4: GND (Ground return — continuous)
    s = s.line([24.0, 106.0], [576.0, 106.0], 3.2, LineCap::Round, gnd_c);
    s = draw_node_pad(s, [24.0, 106.0], 4.5, gnd_c);
    s = draw_node_pad(s, [576.0, 106.0], 4.5, gnd_c);

    // Conductor legend strip above the canvas so labels never collide with vector strokes
    let labels = row()
        .key("schematic-pins")
        .w_full()
        .justify_between()
        .child(pin_chip(theme, "PIN 1 · VBUS +5.0V", vbus_c))
        .child(pin_chip(
            theme,
            if bus_hold_active {
                "PIN 2/3 · D-/D+ HELD OFFLINE"
            } else {
                "PIN 2/3 · D-/D+ RING 3 FILTERED"
            },
            data_left_c,
        ))
        .child(pin_chip(theme, "PIN 4 · GND REF", gnd_c));

    let gate_banner = row()
        .key("schematic-gate-note")
        .w_full()
        .justify_between()
        .center_y()
        .child(
            text("USB Device Bus (BusTypeUsb = 0x07)")
                .font(theme.t_caption)
                .color(theme.ink_muted),
        )
        .child(
            text(if bus_hold_active {
                "MountMgr Pre-Mount Hold (Software Interlock · Pair w/ HW Relay for Physical Cut)"
            } else {
                "Read-Once ShadowCache (I2) → Sandboxed AppContainer CDR → ProjFS/FUSE3"
            })
            .font(theme.t_caption)
            .color(if bus_hold_active {
                theme.danger_fg
            } else {
                theme.info_fg
            }),
        );

    col()
        .key("usb-schematic-wrap")
        .w_full()
        .px(12.0)
        .py(10.0)
        .gap(5.0)
        .radius(8.0)
        .fill(theme.subtle_bg)
        .border(1.0, theme.border_hairline)
        .child(labels)
        .child(
            canvas(s)
                .key("usb-bus-canvas")
                .role("img")
                .label(if bus_hold_active {
                    "USB Bus Schematic: Data paths held offline by software pre-mount interlock"
                } else {
                    "USB Bus Schematic: Data paths active through Ring 3 CDR filter"
                })
                .w_full()
                .h(112.0),
        )
        .child(gate_banner)
}

fn pin_chip(theme: &SentinelTheme, label: &str, dot_color: Color) -> El {
    row()
        .gap(6.0)
        .center_y()
        .child(el().size(7.0, 7.0).radius(3.5).fill(dot_color).a11y_hidden())
        .child(text(label).font(theme.t_mono).color(theme.ink_secondary))
}

fn draw_node_pad(shape: Shape, center: [f32; 2], r: f32, color: Color) -> Shape {
    let mut pts = Vec::with_capacity(12);
    for i in 0..12 {
        let a = std::f32::consts::TAU * (i as f32 / 12.0);
        pts.push([center[0] + r * a.cos(), center[1] + r * a.sin()]);
    }
    shape.fill(pts, color)
}
