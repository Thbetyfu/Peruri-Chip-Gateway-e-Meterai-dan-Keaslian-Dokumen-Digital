#!/usr/bin/env bash
# Jalankan bukti isolasi kunci + kontrol negatif (mutasi yang membocorkan kunci).
set -u
cd "$(dirname "$0")/.."
mkdir -p build/formal

echo "== [1] Desain asli"
if yosys -q -l build/formal/asli.log -s formal/key_isolation.ys >/dev/null 2>&1; then
  echo "   LULUS: $(grep -o 'BUKTI LULUS.*' build/formal/asli.log)"
else
  echo "   GAGAL (lihat build/formal/asli.log)"; exit 1
fi

run_mutant () {   # $1 = nama, $2 = baris case readdata yang disisipkan
  local name="$1" line="$2"
  mkdir -p "build/formal/$name/rtl"
  cp rtl/*.v "build/formal/$name/rtl/"
  python3 - "$name" "$line" <<'EOF'
import sys
name, line = sys.argv[1], sys.argv[2]
p = f"build/formal/{name}/rtl/screener_top.v"
s = open(p).read()
anchor = "        8'h4B: readdata <= cfg_amt_lo;"
assert anchor in s
s = s.replace(anchor, anchor + "\n        " + line)
open(p, "w").write(s)
EOF
  sed "s#rtl/#build/formal/$name/rtl/#g" formal/key_isolation.ys > "build/formal/$name/check.ys"
  if yosys -q -l "build/formal/$name/check.log" -s "build/formal/$name/check.ys" >/dev/null 2>&1; then
    echo "   !! mutan '$name' TIDAK terdeteksi - pengecekan lemah"; return 1
  else
    echo "   terdeteksi: mutan '$name' -> $(grep -o 'Assertion failed.*' "build/formal/$name/check.log" | head -1)"
  fi
}

echo "== [2] Kontrol negatif (RTL sengaja dibocorkan; harus GAGAL)"
fail=0
run_mutant bocor_cache_klien "8'h50: readdata <= c_ipad[31:0];" || fail=1
run_mutant bocor_kunci_token "8'h51: readdata <= v_topad[63:32];" || fail=1
run_mutant bocor_precompute  "8'h52: readdata <= h_st_o[31:0];" || fail=1
exit $fail
