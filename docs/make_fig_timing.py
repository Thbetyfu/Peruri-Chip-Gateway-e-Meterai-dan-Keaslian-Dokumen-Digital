"""Gambar diagram timing satu transaksi dari trace simulasi RTL (build/trace.json)."""
import json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

tr = json.load(open("build/trace.json"))
start = next(i for i, t in enumerate(tr) if t["state"] != 0)
tr = tr[start:]
end = next(i for i, t in enumerate(tr) if t["log_append"]) + 2
tr = tr[:end]
N = len(tr)

def segments(key, f=lambda v: v):
    segs, cur, s0 = [], None, 0
    for i, t in enumerate(tr + [{key: None}]):
        v = f(t[key]) if t[key] is not None else None
        if v != cur:
            if cur is not None:
                segs.append((s0, i - s0, cur))
            cur, s0 = v, i
    return segs

STATE = {1: "Integrity Gate\n(HMAC transaksi)", 2: "Rule", 3: "", 4: "Verdict token + log\n(HMAC berantai)"}
C = {"g": "#2563eb", "r": "#f59e0b", "s": "#10b981", "k": "#64748b"}
fig, ax = plt.subplots(figsize=(11, 3.4), dpi=200)
rows = []

# baris 1: FSM
y = 3
for s, w, v in segments("state"):
    if v in (1, 2, 4):
        col = {1: C["g"], 2: C["r"], 4: C["s"]}[v]
        ax.broken_barh([(s, w)], (y - 0.35, 0.7), color=col)
        ax.text(s + w / 2, y, STATE[v], ha="center", va="center", color="white", fontsize=7, weight="bold")
rows.append("FSM screener_top")

# baris 2: blok SHA-256
y = 2
blk = 0
for s, w, v in segments("core_busy"):
    if v == 1:
        blk += 1
        ax.broken_barh([(s, w)], (y - 0.3, 0.6), color=C["k"])
        ax.text(s + w / 2, y, f"blok {blk}\n{w} cyc", ha="center", va="center", color="white", fontsize=6)
rows.append("sha256_core")

# baris 3: rule engine
y = 1
for s, w, v in segments("rule_ph"):
    if v != 0:
        ax.broken_barh([(s, w)], (y - 0.3, 0.6), color=C["r"])
segs = [s for s in segments("rule_ph") if s[2] != 0]
if segs:
    s0 = segs[0][0]; w0 = sum(s[1] for s in segs)
    ax.annotate(f"rule engine: {w0} cycle", (s0 + w0, y), xytext=(s0 + 25, y + 0.05), fontsize=7, va="center")
rows.append("rule_engine")

# baris 4: log append
y = 0
for i, t in enumerate(tr):
    if t["log_append"]:
        ax.plot([i, i], [y - 0.3, y + 0.3], color=C["s"], lw=2)
        ax.annotate(f"entri log ditulis (cycle {i})", (i, y), xytext=(i - 120, y), fontsize=7, va="center",
                    arrowprops=dict(arrowstyle="->", lw=0.7))
rows.append("audit_log append")

ax.set_yticks(range(len(rows)))
ax.set_yticklabels(rows[::-1], fontsize=8)
ax.set_xlim(0, N)
ax.set_ylim(-0.7, 3.6)
ax.set_xlabel("cycle clock (50 MHz → 20 ns/cycle)", fontsize=8)
ax.tick_params(axis="x", labelsize=7)
ax.set_title(f"Hasil simulasi RTL: satu transaksi diproses dalam {N-2} cycle (≈{(N-2)*20/1000:.1f} µs @ 50 MHz)", fontsize=9)
for sp in ("top", "right"):
    ax.spines[sp].set_visible(False)
ax.grid(axis="x", alpha=0.25)
plt.tight_layout()
plt.savefig("docs/fig/timing_transaksi.png")
print("ok", N - 2)
