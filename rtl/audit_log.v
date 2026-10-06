// SPDX-License-Identifier: Apache-2.0
// audit_log.v - log keputusan tamper-evident (hash-chain) di memori on-chip.
//
// Setiap entri: {seq, verdict, reasons, token}. token = HMAC(K, ... || prev_token)
// dihitung di screener_top, sehingga entri membentuk rantai: mengubah,
// menghapus, menyisipkan, atau menukar urutan entri memutus rantai.
// Host HANYA memiliki port baca; tidak ada jalur tulis dari bus host.
// Buffer cincin 2^DEPTH_BITS entri; entri lama ditimpa tetapi seq & head
// tetap monoton sehingga ekspor periodik dapat diverifikasi berkesinambungan.

`default_nettype none

module audit_log #(
    parameter DEPTH_BITS = 8
) (
    input  wire                  clk,
    input  wire                  rst_n,
    input  wire                  append,
    input  wire [7:0]            verdict,
    input  wire [15:0]           reasons,
    input  wire [255:0]          token,
    output reg  [31:0]           count,     // = seq entri berikutnya
    output reg  [255:0]          head,      // token terakhir (kepala rantai)
    input  wire [DEPTH_BITS-1:0] rd_idx,
    output reg  [31:0]           rd_seq,
    output reg  [31:0]           rd_meta,   // {8'h0, verdict, reasons}
    output reg  [255:0]          rd_token
);
  localparam D = (1 << DEPTH_BITS);
  reg [319:0] mem [0:D-1];
  reg [319:0] rd;

  always @(posedge clk) begin
    if (append) mem[count[DEPTH_BITS-1:0]] <= {count, 8'h00, verdict, reasons, token};
    rd <= mem[rd_idx];
  end

  always @(*) begin
    rd_seq   = rd[319:288];
    rd_meta  = rd[287:256];
    rd_token = rd[255:0];
  end

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      count <= 32'd0; head <= 256'd0;
    end else if (append) begin
      count <= count + 32'd1; head <= token;
    end
  end
endmodule

`default_nettype wire
