"""Demo host PC -> DE10-Nano lewat adaptor USB-UART (115200 8N1).

Pemakaian:  pip install pyserial
            python host/demo_uart.py COM5          (Windows)
            python host/demo_uart.py /dev/ttyUSB0  (Linux)

Skenario: provisioning kunci + LOCK, transaksi sah, bit-flip, replay,
lonjakan (velocity), nominal besar, lalu ekspor & verifikasi rantai log.
"""
import os
import sys
import time

import serial

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "model"))
import golden as G  # noqa: E402

KEY = bytes.fromhex("c0ffee00" * 2 + "5ec0de11" * 2 + "0badf00d" * 2 + "deadbeef" * 2)


class Chip:
    def __init__(self, port):
        self.s = serial.Serial(port, 115200, timeout=1)

    def wr(self, a, d):
        self.s.write(bytes([0x57, a]) + d.to_bytes(4, "big"))
        assert self.s.read(1) == b"K", "tidak ada ACK dari board"

    def rd(self, a):
        self.s.write(bytes([0x52, a]))
        r = self.s.read(4)
        assert len(r) == 4, "timeout baca"
        return int.from_bytes(r, "big")

    def wr_bytes(self, base, b):
        for i, w in enumerate(G.words_be(b)):
            self.wr(base + i, w)

    def rd_bytes(self, base, n):
        return b"".join(self.rd(base + i).to_bytes(4, "big") for i in range(n))

    def submit(self, rec, tag):
        self.wr_bytes(0x00, rec)
        self.wr_bytes(0x10, tag)
        self.wr(0x18, 1)
        while self.rd(0x19) & 0x1:
            pass
        res = self.rd(0x1A)
        return res & 3, (res >> 8) & 0xFFFF, self.rd(0x1B), self.rd_bytes(0x20, 8), self.rd(0x1C)


def main(port):
    c = Chip(port)
    print("== Provisioning kunci & kebijakan, lalu LOCK")
    c.wr_bytes(0x40, KEY)
    c.wr(0x4F, 0x4C4F434B)
    time.sleep(0.01)
    st = c.rd(0x19)
    print(f"   status: locked={bool(st & 4)} tamper={bool(st & 8)}")

    m = G.Screener(KEY)
    tags = []

    def run(label, rec, tag):
        v, r, s, tok, cyc = c.submit(rec, tag)
        ev, er, es, etok = m.process(rec, tag)
        ok = (v, r, s, tok) == (ev, er, es, etok)
        tags.append(tag)
        print(f"   {label:34s} -> {G.VERDICT_NAME[v]:8s} {G.reasons_str(r):18s} "
              f"seq={s} cycles={cyc} {'✓ cocok model' if ok else '✗ BEDA DARI MODEL'}")

    print("== Transaksi")
    r1 = G.make_record(0x1001, 1, 10_000, 1000, b"surat.pdf")
    run("transaksi sah", r1, G.sign_txn(KEY, r1))
    bad = bytearray(G.make_record(0x1001, 2, 10_000, 1001)); t = G.sign_txn(KEY, bytes(bad)); bad[40] ^= 1
    run("satu bit diubah", bytes(bad), t)
    run("replay transaksi pertama", r1, G.sign_txn(KEY, r1))
    for i in range(6):
        r = G.make_record(0x2002, i + 1, 5_000, 2000 + i)
        run(f"lonjakan akun #{i+1}", r, G.sign_txn(KEY, r))
    r = G.make_record(0x3003, 1, 50_000_000, 3000)
    run("nominal besar", r, G.sign_txn(KEY, r))

    print("== Ekspor & verifikasi rantai log")
    entries = []
    for i in range(c.rd(0x30)):
        c.wr(0x31, i); c.rd(0x32)
        meta = c.rd(0x33)
        entries.append({"seq": c.rd(0x32), "verdict": (meta >> 16) & 0xFF, "reasons": meta & 0xFFFF,
                        "txn_tag24": tags[i][:24], "token": c.rd_bytes(0x38, 8)})
    print("  ", G.verify_chain(G.token_key(KEY), entries)[1])
    e = [dict(x) for x in entries]; e[1]["verdict"] = G.ACCEPT; e[1]["reasons"] = 0
    print("   setelah entri #1 dipalsukan:", G.verify_chain(G.token_key(KEY), e)[1])

    print("== Serangan host: tulis ulang kunci setelah LOCK")
    c.wr(0x40, 0x41414141)
    st = c.rd(0x19)
    print(f"   status: locked={bool(st & 4)} tamper={bool(st & 8)} (LED7 menyala)")
    r = G.make_record(0x1001, 99, 1, 9999)
    v, rr, *_ = c.submit(r, G.sign_txn(KEY, r))
    print(f"   transaksi setelah tamper -> {G.VERDICT_NAME[v]} {G.reasons_str(rr)}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "COM5")
