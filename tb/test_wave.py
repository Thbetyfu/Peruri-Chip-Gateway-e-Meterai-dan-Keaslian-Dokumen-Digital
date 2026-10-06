"""Rekam sinyal internal per cycle untuk gambar waveform proposal."""
import json, os, sys
import cocotb
from cocotb.triggers import RisingEdge, ReadOnly
sys.path.insert(0, os.path.dirname(__file__))
import test_screener as T  # noqa: E402
G = T.G

@cocotb.test()
async def record(dut):
    bus = await T.setup(dut)
    await T.provision(bus)
    # Warm the client-key cache before recording the cache-hit path.
    warm = G.make_record(0x1001, 1, 10_000, 1000)
    verdict, _, _, _, _ = await T.submit(bus, warm, G.sign_txn(T.KEY, warm))
    assert verdict == G.ACCEPT
    rec = G.make_record(0x1001, 2, 10_000, 1001)
    tag = G.sign_txn(T.KEY, rec)
    trace = []
    async def sampler():
        while True:
            await RisingEdge(dut.clk); await ReadOnly()
            trace.append({k: int(v.value) for k, v in {
                "state": dut.state, "hmac_busy": dut.u_hmac.busy, "hmac_step": dut.u_hmac.step,
                "core_busy": dut.u_hmac.u_core.busy, "core_rnd": dut.u_hmac.u_core.rnd,
                "rule_ph": dut.u_rule.ph, "log_append": dut.l_append, "done": dut.done_flag,
                "verdict": dut.verdict, "mode": dut.u_hmac.mode}.items()})
    await bus.write_bytes(T.A_TXN, rec); await bus.write_bytes(T.A_TAG, tag)
    h = cocotb.start_soon(sampler())
    await bus.write(T.A_CTRL, 1)
    for _ in range(460):
        await RisingEdge(dut.clk)
    h.cancel()
    result = await bus.read(T.A_RESULT)
    assert (result & 3) == G.ACCEPT, "waveform must show a valid transaction"
    assert await bus.read(T.A_CYC) == 411, "waveform must show the cache-hit path"
    out = os.path.join(os.path.dirname(__file__), "..", "build", "trace.json")
    with open(out, "w", encoding="utf-8") as stream:
        json.dump(trace, stream)
