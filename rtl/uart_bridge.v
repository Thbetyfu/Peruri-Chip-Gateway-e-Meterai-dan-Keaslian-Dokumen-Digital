// SPDX-License-Identifier: Apache-2.0
// uart_bridge.v - jembatan UART 8N1 -> bus register screener (untuk demo PC).
//
// Protokol (byte):
//   Tulis: 'W' addr d3 d2 d1 d0   -> balasan 'K'
//   Baca : 'R' addr               -> balasan d3 d2 d1 d0
// Pada DE10-Nano produksi, jembatan ini digantikan HPS-to-FPGA lightweight
// bridge (Linux di ARM HPS berperan sebagai host server).

`default_nettype none

module uart_bridge #(
    parameter CLK_HZ = 50_000_000,
    parameter BAUD   = 115_200
) (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        rx,
    output reg         tx,
    output reg  [7:0]  address,
    output reg         write,
    output reg  [31:0] writedata,
    output reg         read,
    input  wire [31:0] readdata
);
  localparam integer DIV_I = CLK_HZ / BAUD;
  localparam [15:0] DIV = DIV_I[15:0];
  localparam [15:0] DIV_HALF = DIV >> 1;
  localparam [15:0] DIV_M1 = DIV - 16'd1;

  // ---------------- RX ----------------
  reg [1:0]  rx_s;
  reg [15:0] rx_cnt;
  reg [3:0]  rx_bit;
  reg [7:0]  rx_sh;
  reg        rx_busy, rx_valid;
  reg [7:0]  rx_data;

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      rx_s <= 2'b11; rx_cnt <= 0; rx_bit <= 0; rx_sh <= 0;
      rx_busy <= 0; rx_valid <= 0; rx_data <= 0;
    end else begin
      rx_s <= {rx_s[0], rx};
      rx_valid <= 1'b0;
      if (!rx_busy) begin
        if (!rx_s[1]) begin rx_busy <= 1; rx_cnt <= DIV_HALF; rx_bit <= 0; end
      end else if (rx_cnt != 0) begin
        rx_cnt <= rx_cnt - 1;
      end else begin
        rx_cnt <= DIV_M1;
        if (rx_bit == 0) begin
          if (rx_s[1]) rx_busy <= 0;            // start bit palsu
          else rx_bit <= 1;
        end else if (rx_bit <= 8) begin
          rx_sh <= {rx_s[1], rx_sh[7:1]}; rx_bit <= rx_bit + 1;
        end else begin
          rx_busy <= 0;
          if (rx_s[1]) begin rx_valid <= 1; rx_data <= rx_sh; end
        end
      end
    end
  end

  // ---------------- TX ----------------
  reg [15:0] tx_cnt;
  reg [3:0]  tx_bit;
  reg [9:0]  tx_sh;
  reg        tx_busy, tx_go;
  reg [7:0]  tx_byte;

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      tx <= 1; tx_cnt <= 0; tx_bit <= 0; tx_sh <= 10'h3FF; tx_busy <= 0;
    end else begin
      if (!tx_busy) begin
        if (tx_go) begin
          tx_sh <= {1'b1, tx_byte, 1'b0}; tx_busy <= 1; tx_bit <= 0; tx_cnt <= 0;
        end
      end else if (tx_cnt != 0) begin
        tx_cnt <= tx_cnt - 1;
      end else begin
        if (tx_bit == 10) tx_busy <= 0;
        else begin
          tx <= tx_sh[0]; tx_sh <= {1'b1, tx_sh[9:1]};
          tx_bit <= tx_bit + 1; tx_cnt <= DIV_M1;
        end
      end
    end
  end

  // ---------------- protokol ----------------
  localparam P_CMD = 0, P_ADDR = 1, P_DATA = 2, P_RDWAIT = 3, P_SEND = 4, P_WAITTX = 5, P_RDWAIT2 = 6;
  reg [2:0]  ps;
  reg        is_wr;
  reg [1:0]  nb;
  reg [31:0] resp;
  reg [2:0]  nsend;

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      ps <= P_CMD; is_wr <= 0; nb <= 0; resp <= 0; nsend <= 0;
      address <= 0; write <= 0; writedata <= 0; read <= 0; tx_go <= 0; tx_byte <= 0;
    end else begin
      write <= 0; read <= 0; tx_go <= 0;
      case (ps)
        P_CMD:  if (rx_valid) begin
                  if (rx_data == 8'h57) begin is_wr <= 1; ps <= P_ADDR; end
                  else if (rx_data == 8'h52) begin is_wr <= 0; ps <= P_ADDR; end
                end
        P_ADDR: if (rx_valid) begin
                  address <= rx_data;
                  if (is_wr) begin nb <= 0; ps <= P_DATA; end
                  else begin read <= 1; ps <= P_RDWAIT; end
                end
        P_DATA: if (rx_valid) begin
                  writedata <= {writedata[23:0], rx_data};
                  nb <= nb + 1;
                  if (nb == 2'd3) begin
                    write <= 1; resp <= {8'h4B, 24'd0}; nsend <= 1; ps <= P_SEND;
                  end
                end
        P_RDWAIT:  ps <= P_RDWAIT2;                    // readdata terdaftar 1 cycle
        P_RDWAIT2: begin resp <= readdata; nsend <= 4; ps <= P_SEND; end
        P_SEND: if (!tx_busy && !tx_go) begin
                  tx_byte <= resp[31:24]; resp <= {resp[23:0], 8'h00};
                  tx_go <= 1; nsend <= nsend - 1; ps <= P_WAITTX;
                end
        P_WAITTX: if (tx_busy) ps <= (nsend == 0) ? P_CMD : P_SEND;
        default: ps <= P_CMD;
      endcase
    end
  end
endmodule

`default_nettype wire
