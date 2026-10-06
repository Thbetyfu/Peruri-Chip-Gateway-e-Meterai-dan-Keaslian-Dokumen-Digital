$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$bmp = [Drawing.Bitmap]::new(1600,1800)
$g = [Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.TextRenderingHint = [Drawing.Text.TextRenderingHint]::AntiAliasGridFit
$g.Clear([Drawing.Color]::White)
$font = [Drawing.Font]::new('Arial',22)
$small = [Drawing.Font]::new('Arial',18)
$title = [Drawing.Font]::new('Arial',25,[Drawing.FontStyle]::Bold)
$fmt = [Drawing.StringFormat]::new()
$fmt.Alignment = [Drawing.StringAlignment]::Center
$fmt.LineAlignment = [Drawing.StringAlignment]::Center
function Box($x,$y,$w,$h,$text,$fill,$stroke) {
  $brush = [Drawing.SolidBrush]::new([Drawing.ColorTranslator]::FromHtml($fill))
  $pen = [Drawing.Pen]::new([Drawing.ColorTranslator]::FromHtml($stroke),3)
  $g.FillRectangle($brush,$x,$y,$w,$h)
  $g.DrawRectangle($pen,$x,$y,$w,$h)
  $g.DrawString($text,$font,[Drawing.Brushes]::Black,[Drawing.RectangleF]::new($x+8,$y+8,$w-16,$h-16),$fmt)
  $brush.Dispose(); $pen.Dispose()
}
function Arrow($x1,$y1,$x2,$y2,$color='#475569') {
  $pen = [Drawing.Pen]::new([Drawing.ColorTranslator]::FromHtml($color),3)
  $pen.CustomEndCap = [Drawing.Drawing2D.AdjustableArrowCap]::new(5,6)
  $g.DrawLine($pen,$x1,$y1,$x2,$y2)
  $pen.Dispose()
}
$g.DrawString('Integrity-Gated Transaction Screener',$title,[Drawing.Brushes]::Black,[Drawing.RectangleF]::new(0,10,1600,70),$fmt)
Box 180 105 540 145 "Host: PC UART / Linux HPS`n(tulis TXN + TAG, baca hasil)" '#fde8e8' '#b42318'
Box 900 105 540 145 "Backend: verifikasi dengan K_tok`nTerima transaksi bertoken valid" '#fde8e8' '#b42318'
$boundary = [Drawing.Pen]::new([Drawing.ColorTranslator]::FromHtml('#1d3a6e'),3)
$boundary.DashStyle = [Drawing.Drawing2D.DashStyle]::Dash
$g.DrawRectangle($boundary,65,325,1470,1370)
$g.DrawString('Secure boundary: FPGA fabric Cyclone V 5CSEBA6',$title,[Drawing.Brushes]::Black,[Drawing.RectangleF]::new(100,350,1400,70),$fmt)
$g.DrawString('State kunci / ipad / opad tidak terhubung ke bus host',$small,[Drawing.Brushes]::Black,[Drawing.RectangleF]::new(100,412,1400,45),$fmt)
Box 605 490 440 115 "Bus Avalon-MM 32-bit`nUART / target HPS bridge" '#eef2f7' '#475569'
Box 605 665 440 120 "TXN 64 B + TAG 32 B`nID klien: byte 2-3`nInput dikunci saat busy" '#eef2f7' '#475569'
Box 120 570 390 215 "Key Vault: LOCK`nK_master -> K_tok`nKunci mentah dihapus`nTamper -> zeroize" '#ede9fe' '#6d28d9'
Box 120 875 390 195 "Derivasi K_client di chip`nCache ipad/opad: 1 klien`nCache miss: +5 blok SHA`nCache ikut zeroize" '#ede9fe' '#6d28d9'
Box 605 875 440 160 "1. Integrity Gate`nHMAC(K_client, TXN)`n3 blok SHA-256" '#dbeafe' '#1d4ed8'
Box 1110 875 350 160 "sha256_core bersama`n65 cycle/blok`nK-ROM + schedule" '#f1f5f9' '#475569'
Box 605 1110 440 190 "2. Rule + Account RAM`n64 slot direct-mapped`nNonce + watermark`nVelocity + nominal" '#dcfce7' '#15803d'
Box 120 1190 390 110 "3. Decision Unit`nACCEPT / FLAG /`nESCALATE / REJECT" '#eef2f7' '#475569'
Box 120 1440 520 140 "4. Verdict token`nHMAC(K_tok, verdict | seq |`ntag | token sebelumnya)" '#dbeafe' '#1d4ed8'
Box 900 1440 500 140 "5. Audit Log`nRing 256 entri + keyed chain`nHost hanya membaca" '#fef3c7' '#b45309'
Arrow 180 180 90 180
Arrow 90 180 90 545
Arrow 90 545 605 545
Arrow 1045 545 1495 545
Arrow 1495 545 1495 180
Arrow 1495 180 1440 180
Arrow 825 605 825 665
Arrow 825 785 825 875
Arrow 315 785 315 875 '#6d28d9'
Arrow 510 955 605 955 '#6d28d9'
Arrow 1045 955 1110 955
Arrow 825 1035 825 1110
Arrow 605 1210 510 1245
Arrow 605 1010 420 1190 '#b42318'
$g.FillRectangle([Drawing.Brushes]::White,350,1065,240,60)
$g.DrawString('Tag salah: REJECT',$small,[Drawing.Brushes]::Firebrick,[Drawing.RectangleF]::new(350,1065,240,60),$fmt)
Arrow 315 1300 315 1440
Arrow 120 730 95 730 '#6d28d9'
Arrow 95 730 95 1510 '#6d28d9'
Arrow 95 1510 120 1510 '#6d28d9'
Arrow 640 1510 900 1510
$g.DrawString('token + seq',$small,[Drawing.Brushes]::Black,[Drawing.RectangleF]::new(650,1445,240,60),$fmt)
$g.DrawString('Cache hit: 411 cycle | Cache miss: 750 cycle | 50 MHz',$small,[Drawing.Brushes]::Black,[Drawing.RectangleF]::new(100,1610,1400,60),$fmt)
$bmp.Save((Join-Path $PSScriptRoot 'fig/block_diagram.png'),[Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose(); $font.Dispose(); $small.Dispose(); $title.Dispose(); $fmt.Dispose(); $boundary.Dispose()
