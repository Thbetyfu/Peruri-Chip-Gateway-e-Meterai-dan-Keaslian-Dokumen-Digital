"""Ukur cycle per blok SHA-256 pada baseline TT07 memakai protokol IO aslinya."""
import cocotb
from cocotb.utils import get_sim_time
import tt07_test_orig as T

@cocotb.test()
async def measure(dut):
    meta = await T.test_init(dut)
    t0 = get_sim_time("us")
    await T.test_one_sha_full(dut, meta, b"trans rights")   # 1 blok, hasil dicek vs hashlib
    t1 = get_sim_time("us")
    cycles = int((t1 - t0) / 10)
    dut._log.info("BASELINE TT07: %d cycle per blok 512-bit (termasuk IO host)", cycles)
    with open("baseline_cycles.txt", "w") as f:
        f.write(str(cycles))
