# Verifikasi revisi hierarki kunci dan watermark

RTL yang diuji: commit `3b177f9dcda9afdd087bf6da3475eb0abaf32dbb`.

| Pemeriksaan | Hasil | Bukti |
|---|---|---|
| Core RTL | 13/13 lulus (12 skenario + laporan) | `log_simulasi_core.txt`, `hasil_simulasi.md` |
| UART end-to-end | 1/1 lulus | `log_simulasi_uart.txt` |
| Waveform cache hit | 1/1 lulus; ACCEPT, 411 cycle | `log_simulasi_wave.txt`, `fig/timing_transaksi.png` |
| Regresi 10.000 transaksi | Lulus bit-exact, sesuai update pengguna 7 Oktober 2026 | `tb/test_random.py`; log asli tidak tersedia di checkout lokal |
| Quartus fitter | 4.346 ALM, 8.568 register, 15 M10K, 0 DSP | `quartus/screener.fit.summary` |
| Timing @50 MHz | Fmax worst-case 75,04 MHz; setup +6,673 ns, hold +0,107 ns minimum | `quartus/screener.sta.rpt`, `quartus/screener.sta.summary` |
| Power Analyzer | Successful; 493,84 mW total, confidence Low | `quartus/screener.pow.rpt`, `quartus/screener.pow.summary` |

Latensi sah terukur: cache hit 411 cycle / cache miss 750 cycle. Penolakan integrity: 407 / 746 cycle. Pada 50 MHz, kapasitas core sah sekitar 121.654 / 66.667 transaksi/detik sebelum biaya transfer I/O; pola pergantian klien menentukan tingkat cache miss.

Power Analyzer dijalankan pada database fitted yang tersedia dengan `quartus_pow screener -c screener`, Quartus Prime Lite 24.1. Analisis vectorless, clock 50 MHz, default toggle 12,5%, ambient 25 °C, tanpa model termal board dan tanpa aktivitas HPS. Estimasi dinamis 68,61 mW, statis 412,95 mW, I/O 12,29 mW; komponen dibulatkan sehingga jumlahnya dapat berbeda 0,01 mW dari total. VCD dan pengukuran fisik board diperlukan untuk validasi aktivitas serta konsumsi aktual.

Pemeriksaan Yosys di `formal/` menelusuri fan-in `readdata` dengan batas hierarki `hmac_engine`; pemeriksaan ini tidak membuktikan ketahanan terhadap side-channel atau aliran rahasia melalui keluaran MAC yang memang diizinkan. Skrip dan tiga kontrol negatif tersedia; tidak dijalankan ulang dalam pembaruan dokumen ini.

Proposal dibangun dari sumber DOCX yang dipertahankan di `docs/proposal/`; diagram arsitektur diperbarui, dan PDF diekspor melalui Microsoft Word. LibreOffice tidak tersedia pada mesin ini. QA visual dilakukan terhadap hasil ekspor PDF, satu PNG per halaman.
