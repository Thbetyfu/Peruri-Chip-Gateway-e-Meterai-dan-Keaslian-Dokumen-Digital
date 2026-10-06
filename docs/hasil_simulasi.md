| Skenario | Hasil | Keterangan | Cycle |
|---|---|---|---|
| transaksi sah | ACCEPT | - | 411 |
| bit-flip rekaman bit 255 | REJECT | INTEGRITY | 407 |
| bit-flip rekaman bit 300 | REJECT | INTEGRITY | 407 |
| bit-flip rekaman bit 511 | REJECT | INTEGRITY | 407 |
| bit-flip rekaman bit 76 | REJECT | INTEGRITY | 407 |
| bit-flip rekaman bit 299 | REJECT | INTEGRITY | 407 |
| bit-flip rekaman bit 441 | REJECT | INTEGRITY | 407 |
| bit-flip rekaman bit 418 | REJECT | INTEGRITY | 407 |
| bit-flip pada tag | REJECT | INTEGRITY | 407 |
| transaksi asli setelah serangan | ACCEPT | - | 411 |
| transaksi sah | ACCEPT | - | 411 |
| token disubmit sebagai transaksi | REJECT | DOMAIN | 407 |
| transaksi nonce 10 | ACCEPT | - | 411 |
| replay transaksi yang sama | REJECT | REPLAY | 411 |
| nonce mundur (9) | REJECT | REPLAY | 411 |
| nonce baru (11) | ACCEPT | - | 411 |
| lonjakan akun #1 dlm 60 dtk | ACCEPT | - | 411 |
| lonjakan akun #2 dlm 60 dtk | ACCEPT | - | 411 |
| lonjakan akun #3 dlm 60 dtk | ACCEPT | - | 411 |
| lonjakan akun #4 dlm 60 dtk | ACCEPT | - | 411 |
| lonjakan akun #5 dlm 60 dtk | ACCEPT | - | 411 |
| lonjakan akun #6 dlm 60 dtk | FLAG | VELOCITY | 411 |
| lonjakan akun #7 dlm 60 dtk | FLAG | VELOCITY | 411 |
| setelah jendela waktu lewat | ACCEPT | - | 411 |
| nominal di atas batas | ESCALATE | AMOUNT | 411 |
| log #0 | ESCALATE | AMOUNT | 411 |
| log #1 | ACCEPT | - | 411 |
| log #2 | ESCALATE | AMOUNT | 411 |
| log #3 | ACCEPT | - | 411 |
| log #4 | REJECT | INTEGRITY | 407 |
| log #5 | ACCEPT | - | 411 |
| log #6 | ESCALATE | AMOUNT | 411 |
| log #7 | ACCEPT | - | 411 |
| log #8 | ACCEPT | - | 411 |
| log #9 | ACCEPT | - | 411 |
| verifikasi log asli | OK | rantai utuh (10 entri) | - |
| log: entri REJECT diubah jadi ACCEPT | TERDETEKSI | rantai putus pada seq 4 | - |
| log: entri #6 dihapus | TERDETEKSI | celah/urutan seq: harap 6, dapat 7 | - |
| log: urutan entri ditukar | TERDETEKSI | rantai putus pada seq 2 | - |
| sapu 256 alamat bus: kunci/ipad/opad | TIDAK BOCOR | kunci mentah = 0 setelah LOCK | - |
| sebelum serangan | ACCEPT | - | 411 |
| host menulis ulang kunci setelah LOCK | TAMPER | zeroize, semua REJECT, token=0 | - |
| host melonggarkan aturan setelah LOCK | TAMPER | kebijakan tetap | - |
| sinyal sensor tamper eksternal | TAMPER | zeroize | - |
| chip belum diprovisioning | REJECT | fail-closed | - |
