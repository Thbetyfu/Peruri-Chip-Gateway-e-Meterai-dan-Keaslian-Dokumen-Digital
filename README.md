# Integrity-Gated Transaction Screener
**Secure Element Co-Processor untuk Infrastruktur Keaslian Digital** — PERURI Chip Hackathon 2026, Topik 01 (Secure Identity & Security Element). Tim Paket Kulit 12k, Telkom University.

Co-processor yang dipasang di jalur masuk server. Setiap transaksi diverifikasi HMAC-SHA256 dengan kunci yang **tidak pernah bisa dibaca host**, disaring aturan deterministik (replay, velocity, nominal), lalu diberi **verdict token bertanda tangan** yang sekaligus menjadi mata rantai **audit log tamper-evident**. Host yang sudah di-root tetap tidak bisa mematikan aturan, memalsukan putusan, atau menghapus jejak tanpa ketahuan.

## Struktur
| Folder | Isi |
|---|---|
| `rtl/` | Verilog-2005, tanpa IP vendor: `sha256_round` (turunan TT07), `sha256_core`, `hmac_engine`, `key_vault`, `rule_engine`, `audit_log`, `screener_top`, `uart_bridge`, `de10_nano_top` |
| `model/golden.py` | Golden model Python (referensi bit-exact + verifikator rantai log backend) |
| `tb/` | Testbench cocotb: `test_screener.py` (11 tes), `test_uart.py` (end-to-end lewat UART), `run.py` |
| `baseline/` | Pengukuran baseline TT07 `tt_um_xeniarose_sha256` dengan protokol IO aslinya |
| `quartus/` | Proyek Quartus Prime Lite untuk DE10-Nano (5CSEBA6U23I7) |
| `host/demo_uart.py` | Skrip demo PC → board lewat adaptor USB-UART |
| `docs/` | Hasil simulasi, statistik sintesis Yosys, gambar |

## Hasil saat ini (simulasi RTL, Icarus Verilog + cocotb 2.1)
* 11/11 tes unit lulus + 1 tes end-to-end UART lulus; seluruh verdict & token **bit-exact** dengan golden model.
* Latensi **411 cycle/transaksi** (8,2 µs @ 50 MHz ≈ 121 ribu transaksi/detik per core); transaksi palsu ditolak dalam 407 cycle.
* `sha256_core`: **65 cycle/blok** vs baseline TT07 **1.284 cycle/blok** (diukur) → ±20× lebih cepat, tanpa beban CPU host.
* **Quartus Prime Lite 24.1, kompilasi penuh 5CSEBA6U23I7 (7 Okt 2026):** 3.535 / 41.910 ALM (8%), 7.024 register, 89.600 bit / 13 M10K (2%), 0 DSP, 13 pin. **Fmax 69,9 MHz** worst-case (71,7 MHz @100 °C); setup slack +5,7 ns pada 50 MHz, setup & hold terpenuhi.
* Sintesis silang Yosys `synth_intel_alm -family cyclonev`: ±6.500 LUT, 6.627 FF, 14 M10K.

## Menjalankan simulasi
```bash
sudo apt install iverilog        # atau Icarus for Windows
pip install cocotb pytest
python tb/run.py core    # 11 tes unit
python tb/run.py uart    # tes end-to-end level board (±1 menit)
python tb/run.py wave && python docs/make_fig_timing.py   # gambar timing
```

## Sintesis di Quartus (tanpa board)
1. Install **Quartus Prime Lite** (gratis) + **Cyclone V device support**.
2. *File → Open Project* → `quartus/screener.qpf`.
3. *Processing → Start Compilation* (±5–15 menit).
4. Ambil screenshot / salin angka dari:
   * *Compilation Report → Flow Summary* (Logic utilization ALMs, Total registers, Block memory bits, DSP)
   * *Timing Analyzer → Slow 1100mV 85C Model → Fmax Summary*
5. Kirim angkanya untuk dimasukkan ke tabel resource proposal.

> Pin di `screener.qsf` mengikuti DE10-Nano User Manual Terasic; cek ulang dengan System Builder sebelum memprogram board.

## Demo di board (bootcamp)
Adaptor USB-UART 3.3 V: TX adaptor → GPIO_0[0] (JP1 pin 1), RX adaptor → GPIO_0[1] (JP1 pin 2), GND → GND. KEY0 = reset, KEY1 = sensor tamper. LED[1:0] verdict, LED2 done, LED3 locked, LED7 tamper.
```bash
pip install pyserial
python host/demo_uart.py COM5
```

## Lisensi
Apache-2.0. `sha256_round.v` diturunkan dari *tiny sha256* Tiny Tapeout 7 (© 2024 xenia dragon, Apache-2.0) — lihat `rtl/LICENSE-TT07-sha256-Apache-2.0`.
