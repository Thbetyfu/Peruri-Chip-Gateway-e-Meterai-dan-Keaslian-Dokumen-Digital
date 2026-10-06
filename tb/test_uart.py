"""Tes end-to-end level board: PC -> UART -> uart_bridge -> screener -> UART -> PC."""
import os, sys
import cocotb
from cocotb.clock import Clock
from cocotb.triggers import ClockCycles, Timer, FallingEdge, RisingEdge
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "model"))
import golden as G  # noqa: E402

BIT_NS = 1_000_000_000 // 115_200
KEY = bytes(range(32))

async def uart_send(dut, b):
    dut.uart_rx.value = 0
    await Timer(BIT_NS, unit="ns")
    for i in range(8):
        dut.uart_rx.value = (b >> i) & 1
        await Timer(BIT_NS, unit="ns")
    dut.uart_rx.value = 1
    await Timer(BIT_NS, unit="ns")

async def uart_recv(dut):
    while int(dut.uart_tx.value) == 1:
        await Timer(100, unit="ns")
    await Timer(BIT_NS * 1.5, unit="ns")
    v = 0
    for i in range(8):
        v |= int(dut.uart_tx.value) << i
        await Timer(BIT_NS, unit="ns")
    return v

async def wr(dut, a, d):
    for b in [0x57, a] + list(d.to_bytes(4, "big")):
        await uart_send(dut, b)
    assert await uart_recv(dut) == 0x4B

async def rd(dut, a):
    await uart_send(dut, 0x52); await uart_send(dut, a)
    v = 0
    for _ in range(4):
        v = (v << 8) | await uart_recv(dut)
    return v

@cocotb.test()
async def uart_end_to_end(dut):
    cocotb.start_soon(Clock(dut.clk, 20, unit="ns").start())
    dut.uart_rx.value = 1; dut.key1.value = 1; dut.key0.value = 0
    await ClockCycles(dut.clk, 10); dut.key0.value = 1
    await ClockCycles(dut.clk, 10)
    for i, w in enumerate(G.words_be(KEY)):
        await wr(dut, 0x40 + i, w)
    await wr(dut, 0x4F, 0x4C4F434B)
    assert (await rd(dut, 0x19)) & 0x4, "harus LOCKED"
    m = G.Screener(KEY)
    for label, rec, tag in [
        ("sah", G.make_record(0xABC, 1, 1000, 5), None),
        ("bit-flip", None, None),
    ]:
        if label == "sah":
            tag = G.sign_txn(KEY, rec)
        else:
            rec = bytearray(G.make_record(0xABC, 2, 1000, 6)); tag = G.sign_txn(KEY, bytes(rec)); rec[40] ^= 0x10; rec = bytes(rec)
        for i, w in enumerate(G.words_be(rec)): await wr(dut, i, w)
        for i, w in enumerate(G.words_be(tag)): await wr(dut, 0x10 + i, w)
        await wr(dut, 0x18, 1)
        res = await rd(dut, 0x1A)
        tok = b""
        for i in range(8):
            tok += (await rd(dut, 0x20 + i)).to_bytes(4, "big")
        ev, er, es, etok = m.process(rec, tag)
        assert (res & 3, (res >> 8) & 0xFFFF) == (ev, er) and tok == etok
        assert int(dut.led.value) & 3 == ev
        dut._log.info("UART %-8s -> %s (LED=%s)", label, G.VERDICT_NAME[ev], dut.led.value)
