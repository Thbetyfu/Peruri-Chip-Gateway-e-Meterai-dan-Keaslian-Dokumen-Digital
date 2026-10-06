from pathlib import Path
from cocotb_tools.runner import get_runner
here = Path(__file__).resolve().parent
r = get_runner("icarus")
r.build(sources=[here/"tt07_sha256_project.v"], hdl_toplevel="tt_um_xeniarose_sha256", build_dir=here/"build", always=True, timescale=("1ns","1ps"))
r.test(hdl_toplevel="tt_um_xeniarose_sha256", test_module="measure_baseline", test_dir=here, build_dir=here/"build")
