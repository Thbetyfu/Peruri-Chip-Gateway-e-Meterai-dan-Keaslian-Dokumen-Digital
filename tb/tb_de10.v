// Pembungkus simulasi: memisahkan pin UART dari bus GPIO inout.
`timescale 1ns/1ps
module tb_de10 (input wire clk, input wire key0, input wire key1,
                input wire uart_rx, output wire uart_tx, output wire [7:0] led);
  de10_nano_top dut (.FPGA_CLK1_50(clk), .KEY({key1, key0}), .LED(led),
                     .UART_RX(uart_rx), .UART_TX(uart_tx));
endmodule
