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
    rec = G.make_record(0x1001, 1, 10_000, 1000)
    tag = G.tag_of(T.KEY, rec)
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
    out = os.path.join(os.path.dirname(__file__), "..", "build", "trace.json")
    json.dump(trace, open(out, "w"))
