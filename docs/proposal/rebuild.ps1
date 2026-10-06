param([switch]$ExportPdf)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$source = Join-Path $PSScriptRoot 'Proposal_PERURI_Chip_2026_PaketKulit12k.source.docx'
$target = Join-Path $PSScriptRoot 'Proposal_PERURI_Chip_2026_PaketKulit12k.docx'
Copy-Item -LiteralPath $source -Destination $target -Force
$zip = [IO.Compression.ZipFile]::Open($target, [IO.Compression.ZipArchiveMode]::Update)
try {
    $reader = [IO.StreamReader]::new($zip.GetEntry('word/document.xml').Open())
    [xml]$xml = $reader.ReadToEnd()
    $reader.Dispose()
    $ns = [Xml.XmlNamespaceManager]::new($xml.NameTable)
    $ns.AddNamespace('w','http://schemas.openxmlformats.org/wordprocessingml/2006/main')
    $paragraphs = @($xml.SelectNodes('//w:body//w:p', $ns))
    # Indices refer to the retained source, including paragraphs inside tables.
    $edits = @{
      25 = 'Integrity Gate (HMAC-SHA256) — rekaman diverifikasi dengan kunci khusus klien yang diturunkan di chip; data palsu ditolak sebelum rule engine.'
      26 = 'Rule Engine + Account State Memory — anti-replay melalui nonce per akun dan watermark timestamp per slot, velocity per akun, serta batas nominal.'
      30 = 'Hierarki kunci memisahkan K_master, K_client, dan K_tok. Saat LOCK, chip menurunkan kunci token lalu menghapus kunci mentah; state master dipakai untuk derivasi kunci klien di dalam chip. Klien hanya memegang K_client miliknya; backend memverifikasi token dengan K_tok. Seluruh state kunci tidak terbaca di bus. Tulis ulang kunci/kebijakan atau pin tamper memicu zeroize dan fail-closed.'
      34 = 'RTL lengkap dan golden model tersedia. Regresi acak 10.000 transaksi lulus bit-exact, termasuk pergantian klien dan eviksi akun. Kompilasi penuh Quartus Prime Lite 24.1 untuk 5CSEBA6U23I7 lolos timing: Fmax 75,04 MHz worst-case, 10% ALM, 15 M10K, dan 0 DSP.'
      35 = 'Saat kunci klien berada dalam cache, jalur transaksi tetap 411 cycle (8,22 µs @ 50 MHz; sekitar 121,7 ribu transaksi/detik per core). Cache miss memerlukan 750 cycle (15,00 µs; sekitar 66,7 ribu transaksi/detik @ 50 MHz), termasuk derivasi HMAC dan precompute 5 blok SHA-256 tambahan. Angka ini kapasitas komputasi core, belum termasuk transfer UART dan host.'
      37 = 'Keamanan terhadap host: kunci klien dan token dipisahkan, kebijakan terkunci, watermark mencegah replay transaksi akun yang tergusur, dan keyed hash-chain mendeteksi perubahan log. Pemeriksaan struktural isolasi kunci tersedia bersama tiga kontrol negatif.'
      82 = 'Integrity Gate: jika ID klien byte 2–3 tidak cocok dengan cache satu entri, chip menurunkan K_client = HMAC(K_master, pesan derivasi 64 byte berlabel PERURI-CLIENT-KEY-v1 dan ID klien), lalu precompute ipad/opad. HMAC rekaman memakai state K_client (3 blok SHA-256). Domain/tag salah menghasilkan REJECT sebelum rule engine.'
      83 = 'Rule Engine membaca RAM direct-mapped 64 slot dan mengevaluasi replay, velocity, serta nominal (3 cycle). Tiap slot menyimpan ID akun, nonce, awal jendela, hitungan, timestamp terakhir dan watermark; bit valid disimpan di register. Eviksi menaikkan watermark ke timestamp terbesar akun yang tergusur. Akun yang tidak ditemukan ditolak jika timestamp ≤ watermark. Prioritas verdict: REJECT > ESCALATE > FLAG > ACCEPT.'
      84 = 'Verdict token = HMAC(K_tok, domain‖verdict‖reasons‖seq‖24 byte tag‖token sebelumnya). K_tok diturunkan saat LOCK dari pesan PERURI-TOKEN-KEY-v1 yang dipadatkan menjadi 64 byte. Domain 0x01 transaksi dan 0x02 token, serta pemisahan kunci, mencegah pemakaian token sebagai tag transaksi.'
      111 = 'Tabel 2. Rekaman 64 byte (big-endian); byte 2–3 = ID klien 16-bit. Tag = HMAC-SHA256(K_client, rekaman).'
      127 = 'Derivasi K_tok saat LOCK; state master/token terlindung; kunci mentah dihapus; tanpa port baca'
      130 = 'RAM 64 slot + watermark timestamp per slot (inferable M10K), 3 cycle; bit valid di register'
      136 = 'Derivasi K_client + cache 1 entri; input terkunci saat busy; cache ikut zeroize'
      160 = 'HMAC-SHA256, hierarki master/klien/token, write-once + precompute'
      174 = 'Nonce naik ketat untuk akun yang ditemukan; akun tidak ditemukan wajib memiliki timestamp di atas watermark slot. Transaksi sah yang terlambat dapat ditolak secara konservatif.'
      178 = 'Backend menerima transaksi bertoken valid menggunakan K_tok; K_client tidak dapat menerbitkan verdict token'
      182 = 'Domain byte 0 + pemisahan K_client dan K_tok'
      186 = 'Di luar cakupan prototipe: side-channel, fault injection, dan denial of service. State akun, watermark, dan log masih volatil; proteksi lintas reset membutuhkan checkpoint/counter persisten di backend. ID akun diasumsikan unik lintas klien. Roadmap: PUF, kebijakan bertanda tangan dengan versi anti-rollback, serta countermeasure DPA untuk ASIC.'
      188 = 'Kompilasi penuh Quartus Prime Lite 24.1, 7 Oktober 2026, 5CSEBA6U23I7 (de10_nano_top termasuk UART, hierarki kunci, dan watermark). Laporan fit, timing dan power disimpan dalam repository.'
      193 = '4.346 (10%)'
      196 = '8.568 (±5%)'
      199 = '93.696 bit (15 blok; 3% M10K)'
      208 = '75,04 MHz (Slow −40 °C); 75,29 MHz pada 100 °C. Setup slack minimum +6,673 ns pada 50 MHz; hold minimum +0,107 ns.'
      210 = 'Tabel 6. Utilisasi resource dan timing. Power Analyzer: total 493,84 mW (dinamis 68,61; statis 412,95; I/O 12,29 mW) @ 50 MHz. Estimasi vectorless, default toggle 12,5%, confidence Low; belum ada VCD atau model termal board. Aktivitas HPS tidak dimodelkan; angka bukan pengukuran konsumsi board.'
      218 = 'Testbench membandingkan verdict, reason code, sequence, token, dan kepala rantai log dengan golden model Python. Tes core terbaru 13/13 lulus (12 skenario + laporan). Regresi acak 10.000 transaksi dilaporkan lulus bit-exact pada revisi hierarki kunci dan watermark; mencakup 200 akun pada 64 slot serta 5 klien (seed default 20261007).'
      224 = 'ACCEPT; 411 cycle saat cache hit'
      227 = 'REJECT INTEGRITY; 407 cycle saat cache hit'
      233 = 'REJECT REPLAY; termasuk akun tergusur via watermark'
      242 = 'Tidak ada kebocoran pada sapu bus; cek struktural tersedia'
      255 = 'Tabel 7. Skenario simulasi RTL. Tambahan T11: isolasi kunci antarklien dan token; T12: replay akun tergusur. Regresi acak: 10.000 verdict/token bit-exact. Bukti struktural Yosys membatasi fan-in readdata pada batas hmac_engine; tiga mutan bocor dipakai sebagai kontrol negatif, bukan bukti ketahanan side-channel.'
      257 = 'Gambar 2. Jalur cache hit: 6 blok SHA-256, rule engine 3 cycle, total 411 cycle. Cache miss menambah 5 blok untuk derivasi dan precompute kunci klien; waveform ini menunjukkan jalur cache hit.'
      259 = 'Kompilasi penuh Quartus sudah lolos: 10% ALM, Fmax 75,04 MHz; Power Analyzer vectorless 493,84 mW (Low confidence). Pemrograman .sof lewat USB-Blaster II dan pengukuran daya board dilakukan saat bootcamp.'
      269 = 'Regresi 10.000 transaksi lulus bit-exact'
      271 = '≤ 500 cycle saat cache hit; < 800 saat cache miss'
      272 = '411 cycle cache hit / 750 cycle cache miss (8,22 / 15,00 µs @ 50 MHz)'
      275 = '≈121,7 ribu/detik cache hit / 66,7 ribu cache miss @ 50 MHz (kapasitas core)'
      284 = '75,04 MHz; setup & hold terpenuhi'
      287 = '10% ALM, 3% M10K, 0 DSP — tercapai'
      288 = 'Tabel 8. Metrik keberhasilan. Throughput adalah kapasitas core pada cache hit; pergantian klien dan transfer I/O menurunkan throughput end-to-end. Daya masih estimasi vectorless dan akan divalidasi dengan aktivitas VCD serta pengukuran board.'
      321 = 'Laporan teknis: spesifikasi, peta register, hierarki kunci, watermark, regresi acak, timing, resource, dan estimasi daya beserta batasannya.'
      367 = 'Ukur throughput cache hit/miss dan daya board; bandingkan estimasi vectorless dengan VCD; video, laporan, dan presentasi final'
    }
    foreach ($index in $edits.Keys) {
        $texts = @($paragraphs[$index].SelectNodes('.//w:t', $ns))
        if ($texts.Count -eq 0) { throw "Paragraph $index has no text" }
        $run = $texts[0].ParentNode
        $runPr = $run.SelectSingleNode('w:rPr', $ns)
        if (!$runPr) { $runPr = $xml.CreateElement('w','rPr',$ns.LookupNamespace('w')); [void]$run.PrependChild($runPr) }
        $bold = $runPr.SelectSingleNode('w:b', $ns)
        if (!$bold) { $bold = $xml.CreateElement('w','b',$ns.LookupNamespace('w')); [void]$runPr.AppendChild($bold) }
        [void]$bold.SetAttribute('val',$ns.LookupNamespace('w'),'0')
        $texts[0].InnerText = $edits[$index]
        for ($i=1; $i -lt $texts.Count; $i++) { $texts[$i].InnerText = '' }
    }
    $typeRow = $paragraphs[93].SelectSingleNode('ancestor::w:tr', $ns)
    $clientRow = $typeRow.CloneNode($true)
    $clientCells = @($clientRow.SelectNodes('w:tc', $ns))
    $clientValues = @('2–3', 'ID klien', '16-bit; memilih K_client untuk autentikasi rekaman')
    for ($i=0; $i -lt 3; $i++) {
        $cellTexts = @($clientCells[$i].SelectNodes('.//w:t', $ns))
        $cellTexts[0].InnerText = $clientValues[$i]
        for ($j=1; $j -lt $cellTexts.Count; $j++) { $cellTexts[$j].InnerText = '' }
    }
    [void]$typeRow.ParentNode.InsertAfter($clientRow, $typeRow)
    $imageEntry = 'word/media/0056e97ca90ca248f965dd63f3ab575202818111.png'
    $zip.GetEntry($imageEntry).Delete()
    $imageStream = $zip.CreateEntry($imageEntry).Open()
    $imageBytes = [IO.File]::ReadAllBytes((Join-Path $PSScriptRoot '../fig/block_diagram.png'))
    $imageStream.Write($imageBytes, 0, $imageBytes.Length)
    $imageStream.Dispose()
    $timingEntry = 'word/media/026721377693b119f3b8fa49f6d06579341cfada.png'
    $zip.GetEntry($timingEntry).Delete()
    $timingStream = $zip.CreateEntry($timingEntry).Open()
    $timingBytes = [IO.File]::ReadAllBytes((Join-Path $PSScriptRoot '../fig/timing_transaksi.png'))
    $timingStream.Write($timingBytes, 0, $timingBytes.Length)
    $timingStream.Dispose()
    $zip.GetEntry('word/document.xml').Delete()
    $entry = $zip.CreateEntry('word/document.xml')
    $writer = [IO.StreamWriter]::new($entry.Open(), [Text.UTF8Encoding]::new($false))
    $writer.Write($xml.OuterXml)
    $writer.Dispose()
} finally { $zip.Dispose() }
if ($ExportPdf) {
    $word = New-Object -ComObject Word.Application
    $word.Visible = $false
    $word.DisplayAlerts = 0
    try {
        $doc = $word.Documents.Open($target, $false, $true)
        $doc.ExportAsFixedFormat([IO.Path]::ChangeExtension($target, '.pdf'), 17)
        $doc.Close(0)
    } finally { $word.Quit() }
}
Write-Output "Built $target"
