// SPDX-License-Identifier: Apache-2.0
// hmac_engine.v - HMAC-SHA256 untuk pesan tetap 64 byte, dengan precompute.
//
// Mode PRECOMP (dipakai sekali saat provisioning):
//   st_i = Compress(IV, K ^ ipad), st_o = Compress(IV, K ^ opad)        -> 2 blok
// Mode MAC (setiap transaksi), memakai st_i/st_o hasil precompute:
//   x     = Compress(st_i, M)                     ; M = 64 byte pesan
//   inner = Compress(x, PAD(len = 128 byte))
//   mac   = Compress(st_o, inner || PAD(len = 96 byte))                 -> 3 blok
// HMAC standar tanpa precompute memerlukan 5 blok per pesan; precompute
// menghemat 2 blok (~40%) dan membuat kunci mentah tidak perlu disimpan.

`default_nettype none

module hmac_engine (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire         mode_precomp,  // 1 = PRECOMP, 0 = MAC
    input  wire [511:0] msg,           // MAC: pesan 64 byte; PRECOMP: blok kunci
    input  wire [255:0] ipad_state,
    input  wire [255:0] opad_state,
    output reg          busy,
    output reg          done,
    output reg  [255:0] mac_out,
    output reg  [255:0] pc_st_i,
    output reg  [255:0] pc_st_o
);
  localparam [255:0] IV = {32'h6a09e667, 32'hbb67ae85, 32'h3c6ef372, 32'ha54ff53a,
                           32'h510e527f, 32'h9b05688c, 32'h1f83d9ab, 32'h5be0cd19};
  // padding blok kedua inner: 0x80, nol, panjang 1024 bit
  localparam [511:0] PAD_INNER = {8'h80, 440'd0, 64'd1024};

  reg         core_start;
  reg [255:0] core_init;
  reg [511:0] core_blk;
  wire        core_busy, core_done;
  wire [255:0] core_dig;

  sha256_core u_core (
    .clk(clk), .rst_n(rst_n), .start(core_start),
    .init_state(core_init), .block(core_blk),
    .busy(core_busy), .done(core_done), .digest(core_dig)
  );

  reg         mode;
  reg [1:0]   step;
  reg         wait_core;
  reg [511:0] msg_r;

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      busy <= 1'b0; done <= 1'b0; mac_out <= 256'd0;
      pc_st_i <= 256'd0; pc_st_o <= 256'd0;
      core_start <= 1'b0; core_init <= 256'd0; core_blk <= 512'd0;
      mode <= 1'b0; step <= 2'd0; wait_core <= 1'b0; msg_r <= 512'd0;
    end else begin
      done <= 1'b0;
      core_start <= 1'b0;

      if (start && !busy) begin
        busy <= 1'b1; mode <= mode_precomp; step <= 2'd0; msg_r <= msg;
        core_start <= 1'b1; wait_core <= 1'b1;
        if (mode_precomp) begin
          core_init <= IV;          core_blk <= msg ^ {64{8'h36}};
        end else begin
          core_init <= ipad_state;  core_blk <= msg;
        end
      end else if (busy && wait_core && core_done) begin
        if (mode) begin
          // ---------------- PRECOMP ----------------
          if (step == 2'd0) begin
            pc_st_i <= core_dig;
            core_init <= IV; core_blk <= msg_r ^ {64{8'h5c}};
            core_start <= 1'b1; step <= 2'd1;
          end else begin
            pc_st_o <= core_dig;
            busy <= 1'b0; done <= 1'b1; wait_core <= 1'b0;
            msg_r <= 512'd0; core_blk <= 512'd0;   // hapus salinan kunci
          end
        end else begin
          // ---------------- MAC ----------------
          case (step)
            2'd0: begin
              core_init <= core_dig; core_blk <= PAD_INNER;
              core_start <= 1'b1; step <= 2'd1;
            end
            2'd1: begin
              core_init <= opad_state;
              core_blk  <= {core_dig, 8'h80, 184'd0, 64'd768};
              core_start <= 1'b1; step <= 2'd2;
            end
            default: begin
              mac_out <= core_dig;
              busy <= 1'b0; done <= 1'b1; wait_core <= 1'b0;
              core_init <= 256'd0; core_blk <= 512'd0;
            end
          endcase
        end
      end
    end
  end
endmodule

`default_nettype wire
