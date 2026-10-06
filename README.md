# Integrity-Gated Transaction Screener
**Secure Element Co-Processor untuk Infrastruktur Keaslian Digital** — PERURI Chip Hackathon 2026, Topik 01 (Secure Identity & Security Element). Tim Paket Kulit 12k, Telkom University.

Co-processor yang dipasang di jalur masuk server. Setiap transaksi diverifikasi HMAC-SHA256 dengan kunci yang **tidak pernah bisa dibaca host**, disaring aturan deterministik (replay, velocity, nominal), lalu diberi **verdict token bertanda tangan** yang sekaligus menjadi mata rantai **audit log tamper-evident**. Host yang sudah di-root tetap tidak bisa mematikan aturan, memalsukan putusan, atau menghapus jejak tanpa ketahuan.

## Struktur
| Folder | Isi |
|---|---|
| `rtl/` | Verilog-2005, tanpa IP vendor: `sha256_round` (turunan TT07), `sha256_core`, `hmac_engine`, `key_vault`, `rule_engine`, `audit_log`, `screener_top`, `uart_bridge`, `de10_nano_top` |
| `model/golden.py` | Golden model Python (referensi bit-exact + verifikator rantai log backend) |
| `tb/` | Testbench cocotb: `test_screener.py` (12 skenario + laporan), `test_uart.py`, `test_random.py`, `run.py` |
| `baseline/` | Pengukuran baseline TT07 `tt_um_xeniarose_sha256` dengan protokol IO aslinya |
| `quartus/` | Proyek Quartus Prime Lite untuk DE10-Nano (5CSEBA6U23I7) |
| `host/demo_uart.py` | Skrip demo PC → board lewat adaptor USB-UART |
| `docs/` | Hasil simulasi, laporan Quartus, gambar, proposal DOCX/PDF dan skrip build |
| `formal/` | Pemeriksaan struktural isolasi kunci Yosys dan tiga kontrol negatif |

## Hasil saat ini (simulasi RTL, Icarus Verilog + cocotb 2.1)
* **13/13 tes core lulus** (12 skenario + laporan), termasuk isolasi kunci antarklien dan replay akun yang tergusur; verdict & token **bit-exact** dengan golden model. Tes end-to-end UART juga lulus.
* Regresi acak **10.000 transaksi lulus bit-exact**, sesuai update hasil pengujian pengguna pada 7 Oktober 2026. Log regresi tersebut tidak tersedia di checkout ini; konfigurasi default: seed 20261007, 200 akun / 64 slot, 5 klien.
* Latensi **411 cycle saat cache hit / 750 cycle saat cache miss** (8,22 / 15,00 µs @ 50 MHz). Kapasitas core ≈121,7 / 66,7 ribu transaksi/detik; transfer UART/host belum termasuk. Transaksi palsu ditolak dalam 407 / 746 cycle.
* `sha256_core`: **65 cycle/blok** vs baseline TT07 **1.284 cycle/blok** (diukur) → ±20× lebih cepat, tanpa beban CPU host.
* **Quartus Prime Lite 24.1, kompilasi penuh 5CSEBA6U23I7 (7 Okt 2026):** **4.346 / 41.910 ALM (10%)**, 8.568 register, 93.696 bit / **15 M10K (3%)**, 0 DSP, 13 pin. **Fmax 75,04 MHz** worst-case (75,29 MHz @100 °C); setup slack minimum +6,673 ns pada 50 MHz, hold minimum +0,107 ns.
* **Power Analyzer: 493,84 mW** total (68,61 mW dinamis + 412,95 mW statis + 12,29 mW I/O). Estimasi vectorless @50 MHz, default toggle 12,5%, **confidence Low**; belum menggunakan VCD/model termal board atau memodelkan aktivitas HPS. Bukan pengukuran konsumsi daya board.
* Hasil sintesis silang Yosys sebelumnya (±6.500 LUT, 6.627 FF, 14 M10K) berasal dari revisi sebelum hierarki kunci/watermark; bukan resource revisi terbaru.

## Hierarki kunci dan state akun
`K_tok` diturunkan saat LOCK; `K_client` diturunkan di chip menggunakan ID klien pada byte 2–3 rekaman dan di-cache satu entri. Klien memegang kunci miliknya, backend memverifikasi token dengan `K_tok`. Kunci mentah dihapus setelah LOCK; state turunan tetap terlindung dari bus dan ikut zeroize.

Account State Memory memakai 64 slot RAM direct-mapped: ID akun, nonce, awal jendela, hitungan, timestamp terakhir, dan watermark per slot. Akun yang tidak ditemukan harus memiliki timestamp di atas watermark; transaksi sah yang terlambat dapat ditolak. State/log masih volatil, sehingga proteksi lintas reset membutuhkan checkpoint/counter persisten. ID akun diasumsikan unik lintas klien.

## Menjalankan simulasi
```bash
sudo apt install iverilog        # atau Icarus for Windows
pip install cocotb pytest
python tb/run.py core    # 12 skenario + 1 laporan
python tb/run.py uart    # tes end-to-end level board (±1 menit)
python tb/run.py random  # default 10.000 transaksi; RANDOM_N dan RANDOM_SEED dapat diatur
python tb/run.py wave && python docs/make_fig_timing.py   # gambar timing
```

## Sintesis di Quartus (tanpa board)
1. Install **Quartus Prime Lite** (gratis) + **Cyclone V device support**.
2. *File → Open Project* → `quartus/screener.qpf`.
3. *Processing → Start Compilation* (±5–15 menit).
4. Ambil screenshot / salin angka dari:
   * *Compilation Report → Flow Summary* (Logic utilization ALMs, Total registers, Block memory bits, DSP)
   * *Timing Analyzer → Slow 1100mV -40C / 100C Model → Fmax Summary*
5. Jalankan *Processing → Start → Power Analyzer*; simpan confidence dan asumsi aktivitas bersama angka daya.

CLI dari folder `quartus/`: `quartus_pow screener -c screener`. Laporan yang dapat ditinjau tersedia di [`docs/quartus/`](docs/quartus/), termasuk laporan lengkap power dan timing.

## Proposal
Proposal terbaru tersedia di [`docs/proposal/`](docs/proposal/) (DOCX dan PDF). Build dengan PowerShell: `./docs/make_fig_architecture.ps1`, lalu `./docs/proposal/rebuild.ps1 -ExportPdf`. Ekspor PDF memakai Microsoft Word yang terpasang. Sumber DOCX dipertahankan agar build dapat diulang. Identitas anggota/pembimbing yang belum diberikan tetap berupa placeholder.

> Pin di `screener.qsf` mengikuti DE10-Nano User Manual Terasic; cek ulang dengan System Builder sebelum memprogram board.

## Demo di board (bootcamp)
Adaptor USB-UART 3.3 V: TX adaptor → GPIO_0[0] (JP1 pin 1), RX adaptor → GPIO_0[1] (JP1 pin 2), GND → GND. KEY0 = reset, KEY1 = sensor tamper. LED[1:0] verdict, LED2 done, LED3 locked, LED7 tamper.
```bash
pip install pyserial
python host/demo_uart.py COM5
```

## Lisensi
Apache-2.0. `sha256_round.v` diturunkan dari *tiny sha256* Tiny Tapeout 7 (© 2024 xenia dragon, Apache-2.0) — lihat `rtl/LICENSE-TT07-sha256-Apache-2.0`.
