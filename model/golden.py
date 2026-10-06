"""Golden model (referensi Python) untuk Integrity-Gated Transaction Screener.

Dipakai oleh testbench cocotb dan skrip host demo. Semua perilaku chip
(HMAC, aturan, verdict token, rantai log) direplikasi di sini sehingga
RTL dapat dibandingkan bit-per-bit.
"""
import hashlib
import hmac
import struct
from dataclasses import dataclass, field

DOM_TXN = 0x01
DOM_TOKEN = 0x02

ACCEPT, FLAG, ESCALATE, REJECT = 0, 1, 2, 3
VERDICT_NAME = {ACCEPT: "ACCEPT", FLAG: "FLAG", ESCALATE: "ESCALATE", REJECT: "REJECT"}

R_INTEGRITY, R_REPLAY, R_VELOCITY, R_AMOUNT, R_DOMAIN, R_VAULT = (1 << i for i in range(6))
REASON_NAME = {R_INTEGRITY: "INTEGRITY", R_REPLAY: "REPLAY", R_VELOCITY: "VELOCITY",
               R_AMOUNT: "AMOUNT", R_DOMAIN: "DOMAIN", R_VAULT: "VAULT"}


def reasons_str(r: int) -> str:
    return "|".join(n for b, n in REASON_NAME.items() if r & b) or "-"


def make_record(account: int, nonce: int, amount: int, tstamp: int,
                doc: bytes = b"dokumen", ttype: int = 1, domain: int = DOM_TXN) -> bytes:
    """Rekaman transaksi 64 byte (lihat format di screener_top.v)."""
    doc_hash = hashlib.sha256(doc).digest()
    rec = struct.pack(">BBHIQQQ", domain, ttype, 0, tstamp, nonce, account, amount) + doc_hash
    assert len(rec) == 64
    return rec


def tag_of(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def token_msg(verdict: int, reasons: int, seq: int, txn_tag: bytes, prev: bytes) -> bytes:
    m = struct.pack(">BBHI", DOM_TOKEN, verdict, reasons, seq) + txn_tag[:24] + prev
    assert len(m) == 64
    return m


@dataclass
class Policy:
    window: int = 60
    vel_limit: int = 5
    amount_limit: int = 10_000_000


@dataclass
class Screener:
    key: bytes
    policy: Policy = field(default_factory=Policy)
    idx_bits: int = 6
    table: dict = field(default_factory=dict)
    seq: int = 0
    head: bytes = bytes(32)
    log: list = field(default_factory=list)

    def process(self, rec: bytes, tag: bytes):
        """Kembalikan (verdict, reasons, seq, token) persis seperti RTL."""
        domain = rec[0]
        tstamp, nonce, account, amount = struct.unpack(">IQQQ", rec[4:32])
        calc = tag_of(self.key, rec)
        if domain != DOM_TXN or calc != tag:
            verdict = REJECT
            reasons = (R_DOMAIN if domain != DOM_TXN else 0) | (R_INTEGRITY if calc != tag else 0)
        else:
            idx = account & ((1 << self.idx_bits) - 1)
            ent = self.table.get(idx)
            hit = ent is not None and ent["acct"] == account
            replay = hit and nonce <= ent["nonce"]
            in_win = hit and ((tstamp - ent["win"]) & 0xFFFFFFFF) < self.policy.window
            win = ent["win"] if in_win else tstamp
            cnt = min(ent["cnt"] + 1, 0xFFFF) if in_win else 1
            vel = (not replay) and cnt > self.policy.vel_limit
            amt = (not replay) and amount > self.policy.amount_limit
            if not replay:
                self.table[idx] = {"acct": account, "nonce": nonce, "win": win, "cnt": cnt}
            reasons = (R_REPLAY if replay else 0) | (R_VELOCITY if vel else 0) | (R_AMOUNT if amt else 0)
            verdict = REJECT if replay else ESCALATE if amt else FLAG if vel else ACCEPT
        seq = self.seq
        token = tag_of(self.key, token_msg(verdict, reasons, seq, tag, self.head))
        self.log.append({"seq": seq, "verdict": verdict, "reasons": reasons,
                         "txn_tag24": tag[:24], "token": token})
        self.seq += 1
        self.head = token
        return verdict, reasons, seq, token


def verify_chain(key: bytes, entries, start_prev: bytes = bytes(32), start_seq: int = 0):
    """Verifikator backend: periksa urutan seq dan setiap mata rantai token.

    entries: list dict {seq, verdict, reasons, txn_tag24, token}
    Kembalikan (ok, pesan).
    """
    prev, exp_seq = start_prev, start_seq
    for e in entries:
        if e["seq"] != exp_seq:
            return False, f"celah/urutan seq: harap {exp_seq}, dapat {e['seq']}"
        m = struct.pack(">BBHI", DOM_TOKEN, e["verdict"], e["reasons"], e["seq"]) + e["txn_tag24"] + prev
        if not hmac.compare_digest(tag_of(key, m), e["token"]):
            return False, f"rantai putus pada seq {e['seq']}"
        prev, exp_seq = e["token"], exp_seq + 1
    return True, f"rantai utuh ({len(entries)} entri)"


def words_be(b: bytes):
    return list(struct.unpack(f">{len(b)//4}I", b))
