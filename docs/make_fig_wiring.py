"""Diagram wiring demo DE10-Nano (laptop + USB-UART + USB-Blaster)."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Rectangle, Circle
from matplotlib import font_manager as fm
import os

for f in fm.findSystemFonts():
    if "Inter" in os.path.basename(f):
        fm.fontManager.addfont(f)
plt.rcParams["font.family"] = "Inter"

INK = "#1f2937"
MUTED = "#6b7280"
C_TX = "#d97706"   # adaptor TX -> FPGA RX
C_RX = "#16a34a"   # FPGA TX -> adaptor RX
C_GND = "#111827"
C_USB = "#2563eb"
C_PWR = "#dc2626"

fig, ax = plt.subplots(figsize=(11, 6.4), dpi=200)
ax.set_xlim(0, 110)
ax.set_ylim(0, 64)
ax.axis("off")


def box(x, y, w, h, fc, ec, lw=1.6, r=1.2, z=1):
    p = FancyBboxPatch((x, y), w, h, boxstyle=f"round,pad=0,rounding_size={r}",
                       fc=fc, ec=ec, lw=lw, zorder=z)
    ax.add_patch(p)
    return p


def label(x, y, s, size=9, color=INK, weight="normal", ha="center", va="center", z=5):
    ax.text(x, y, s, fontsize=size, color=color, weight=weight, ha=ha, va=va, zorder=z)


# ------------------------------------------------------------ laptop
box(2, 30, 22, 22, "#f3f4f6", INK)
label(13, 48.5, "Laptop / PC", 11, weight="bold")
label(13, 45.2, "Quartus Programmer\nhost/demo_uart.py", 8, MUTED)
for i, (yy, t) in enumerate([(38.5, "USB-A #1"), (33.5, "USB-A #2")]):
    box(19, yy - 1.4, 5, 2.8, "#e5e7eb", INK, lw=1.0, r=0.4, z=2)
    label(16.6, yy, t, 7.5, ha="right")

# ------------------------------------------------------------ USB-UART adapter
box(31.5, 29.5, 19.5, 13, "#fff7ed", "#c2410c")
label(41.25, 40.3, "Adaptor USB-UART", 9.5, weight="bold")
label(41.25, 38.0, "(CP2102 / CH340 / FT232)", 7, MUTED)
label(39.5, 35.9, "jumper level = 3,3 V", 7.5, "#c2410c", weight="bold")
pins_ad = {"TXD": 33.0, "RXD": 31.6, "GND": 30.2}
# kaki pin adaptor di sisi kanan
for name, yy in [("TXD", 34.0), ("RXD", 32.6), ("GND", 31.2)]:
    ax.add_patch(Rectangle((51, yy - 0.45), 1.6, 0.9, fc="#9ca3af", ec=INK, lw=0.6, zorder=3))
    label(50.2, yy, name, 7.5, ha="right")
    pins_ad[name] = (52.6, yy)
box(29.5, 34.9, 2.4, 1.6, "#e5e7eb", INK, lw=0.8, r=0.3, z=2)  # konektor USB adaptor

# ------------------------------------------------------------ DE10-Nano board
bx, by, bw, bh = 58, 6, 50, 52
box(bx, by, bw, bh, "#0f5132", "#052e1c", lw=2, r=1.8)
label(bx + bw / 2, by + bh - 2.6, "Terasic DE10-Nano", 12, "white", weight="bold")
label(bx + bw / 2, by + bh - 5.2, "Cyclone V SoC 5CSEBA6U23I7", 8.5, "#bbf7d0")

# chip
box(91, 24, 14, 13, "#111827", "#000000", lw=1.2, r=0.6, z=2)
label(98, 33.0, "Cyclone V", 9, "white", weight="bold")
label(98, 30.6, "SoC FPGA", 8, "#d1d5db")
label(98, 27.2, "screener\n(FPGA fabric)", 7, "#93c5fd")

# JP1 / GPIO_0 header 2x20 di sisi kiri board
hx, hy = 61.5, 14.5
pitch = 1.05
ax.add_patch(Rectangle((hx - 0.9, hy - 0.9), 3.9, 20 * pitch + 0.8, fc="#1f2937", ec="#000", lw=0.8, zorder=2))
pin_xy = {}
for row in range(20):
    for col in range(2):
        n = row * 2 + col + 1          # pin 1 di atas-kiri
        x = hx + col * 2.1
        y = hy + (19 - row) * pitch
        pin_xy[n] = (x, y)
        hl = n in (1, 2, 12)
        fc = {1: C_TX, 2: C_RX, 12: "#e5e7eb"}.get(n, "#d4af37")
        ax.add_patch(Circle((x, y), 0.36 if not hl else 0.48, fc=fc, ec="#000", lw=0.5, zorder=4))
label(hx + 1.05, hy + 20 * pitch + 3.2, "JP1\n(GPIO_0)", 7.5, "white", weight="bold")
label(hx + 4.0, pin_xy[1][1], "pin 1  GPIO_0[0]  PIN_V12  → UART_RX", 6.8, "#fde68a", ha="left")
label(hx + 4.0, pin_xy[2][1] - 1.7, "pin 2  GPIO_0[1]  PIN_E8   → UART_TX", 6.8, "#bbf7d0", ha="left")
label(hx + 4.0, pin_xy[12][1], "pin 12 GND", 6.8, "#e5e7eb", ha="left")

# USB-Blaster mini-USB & DC jack (tepi atas board)
box(95, 50.6, 5, 2.6, "#d1d5db", INK, lw=1.0, r=0.4, z=3)
label(97.5, 48.8, "USB-Blaster II\n(mini-USB)", 6.8, "white")
box(101.5, 50.6, 4.5, 2.6, "#111827", "#9ca3af", lw=1.0, r=0.6, z=3)
label(103.8, 48.8, "DC 5 V", 6.8, "white")

# tombol & LED (tepi bawah)
for i, (xx, t) in enumerate([(96.5, "KEY0\nreset"), (102.5, "KEY1\ntamper")]):
    ax.add_patch(Rectangle((xx - 1.2, 9.2), 2.4, 2.4, fc="#9ca3af", ec="#000", lw=0.6, zorder=3))
    ax.add_patch(Circle((xx, 10.4), 0.7, fc="#374151", ec="#000", lw=0.5, zorder=4))
    label(xx, 6.9 + 0.2, t, 6.3, "white")
led_cols = ["#facc15"] * 2 + ["#60a5fa", "#a78bfa", "#374151", "#374151", "#374151", "#f87171"]
for i in range(8):
    xx = 72 + i * 1.8
    ax.add_patch(Rectangle((xx - 0.5, 15.0), 1.0, 1.6, fc=led_cols[i], ec="#000", lw=0.4, zorder=3))
label(78.3, 12.6, "LED0-1 verdict · LED2 done\nLED3 locked · LED7 tamper", 6.3, "white")
label(78.3, 18.0, "LED[7:0]", 6.5, "#d1d5db")

# ------------------------------------------------------------ kabel
def wire(p0, p1, color, lw=2.2, via=None, ls="-"):
    xs, ys = [p0[0]], [p0[1]]
    for v in (via or []):
        xs.append(v[0]); ys.append(v[1])
    xs.append(p1[0]); ys.append(p1[1])
    ax.plot(xs, ys, color=color, lw=lw, solid_capstyle="round", ls=ls, zorder=6)

# TX adaptor -> pin 1 (FPGA RX)
wire(pins_ad["TXD"], pin_xy[1], C_TX, via=[(55.0, pins_ad["TXD"][1]), (55.0, pin_xy[1][1])])
# RX adaptor <- pin 2 (FPGA TX)
wire(pins_ad["RXD"], pin_xy[2], C_RX, via=[(56.0, pins_ad["RXD"][1]), (56.0, pin_xy[2][1] + 1.6), (pin_xy[2][0], pin_xy[2][1] + 1.6)])
# GND -> pin 12
wire(pins_ad["GND"], pin_xy[12], C_GND, via=[(57.0, pins_ad["GND"][1]), (57.0, pin_xy[12][1])])

# USB laptop -> adaptor
wire((24, 33.5), (29.5, 35.7), C_USB, lw=2.6, via=[(26.8, 33.5), (26.8, 35.7)])
label(26.8, 31.6, "USB", 7, C_USB, weight="bold")
# USB laptop -> USB-Blaster
wire((24, 38.5), (97.5, 53.2), C_USB, lw=2.6, via=[(28, 38.5), (28, 58.5), (97.5, 58.5)])
label(62, 59.6, "Kabel USB (A ↔ mini-B): program FPGA lewat USB-Blaster II", 7.5, C_USB, weight="bold")
# daya
wire((103.8, 53.2), (103.8, 61.5), C_PWR, lw=2.6)
label(103.8, 62.6, "Adaptor 5 V / 2 A", 7.5, C_PWR, weight="bold")

# ------------------------------------------------------------ legenda
lx, ly = 2, 22
box(lx, 3, 53, 21, "white", "#d1d5db", lw=1.0, r=0.8)
label(lx + 1.5, ly, "Sambungan", 9, weight="bold", ha="left")
rows = [
    (C_TX, "TXD adaptor  →  JP1 pin 1  (GPIO_0[0], PIN_V12) = UART_RX FPGA"),
    (C_RX, "RXD adaptor  ←  JP1 pin 2  (GPIO_0[1], PIN_E8)  = UART_TX FPGA"),
    (C_GND, "GND adaptor  —  JP1 pin 12 (GND)"),
    (C_USB, "USB laptop → adaptor UART & USB-Blaster II"),
    (C_PWR, "Adaptor daya 5 V → jack DC board"),
]
for i, (c, t) in enumerate(rows):
    yy = ly - 3 - i * 2.6
    ax.plot([lx + 1.5, lx + 5], [yy, yy], color=c, lw=2.6)
    label(lx + 6, yy, t, 7.3, ha="left")
label(lx + 1.5, 5.2, "⚠ Level logika 3,3 V. Pin VCC adaptor TIDAK disambungkan. 115200 bps, 8N1.",
      7.2, "#b91c1c", weight="bold", ha="left")

plt.savefig(os.path.join(os.path.dirname(__file__), "fig", "wiring_de10nano.png"),
            bbox_inches="tight", facecolor="white")
print("ok")
