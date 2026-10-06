// SPDX-License-Identifier: Apache-2.0
// de10_nano_top.v - pembungkus board DE10-Nano (Cyclone V SoC 5CSEBA6U23I7).
//   FPGA_CLK1_50 : clock 50 MHz
//   KEY[0]       : reset (aktif rendah)
//   KEY[1]       : simulasi sensor tamper (tekan = tamper)
//   UART_RX      : GPIO_0[0] (header JP1 pin 1) <- TX adaptor USB-UART 3.3V
//   UART_TX      : GPIO_0[1] (header JP1 pin 2) -> RX adaptor USB-UART 3.3V
//   LED[1:0]     : verdict terakhir, LED[2] done, LED[3] locked, LED[7] tamper

`default_nettype none

module de10_nano_top (
    input  wire       FPGA_CLK1_50,
    input  wire [1:0] KEY,
    output wire [7:0] LED,
    input  wire       UART_RX,
    output wire       UART_TX
);
  // sinkronisasi reset
  reg [2:0] rst_sync;
  always @(posedge FPGA_CLK1_50 or negedge KEY[0])
    if (!KEY[0]) rst_sync <= 3'b000;
    else         rst_sync <= {rst_sync[1:0], 1'b1};
  wire rst_n = rst_sync[2];

  wire [7:0]  address;
  wire        write, read;
  wire [31:0] writedata, readdata;
  wire        irq_done, st_locked, st_tamper;
  wire [1:0]  st_verdict;

  uart_bridge u_bridge (
    .clk(FPGA_CLK1_50), .rst_n(rst_n), .rx(UART_RX), .tx(UART_TX),
    .address(address), .write(write), .writedata(writedata),
    .read(read), .readdata(readdata)
  );

  screener_top u_screener (
    .clk(FPGA_CLK1_50), .rst_n(rst_n), .tamper_n(KEY[1]),
    .address(address), .write(write), .writedata(writedata),
    .read(read), .readdata(readdata),
    .irq_done(irq_done), .st_locked(st_locked), .st_tamper(st_tamper),
    .st_verdict(st_verdict)
  );

  assign LED = {st_tamper, 3'b000, st_locked, irq_done, st_verdict};
endmodule

`default_nettype wire
