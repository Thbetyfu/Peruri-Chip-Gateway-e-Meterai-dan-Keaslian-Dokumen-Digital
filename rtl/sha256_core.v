// SPDX-License-Identifier: Apache-2.0
// -----------------------------------------------------------------------------
// sha256_core.v  -  Iterative SHA-256 compression engine (1 round / cycle)
//
// Delta design terhadap baseline Tiny Tapeout 7 "tiny sha256"
// (tt_um_xeniarose_sha256, (c) 2024 xenia dragon, Apache-2.0):
//   * Fungsi ronde (s0, s1, ch, maj, temp1, temp2) diadopsi dari baseline
//     dan dipisah ke modul sha256_round.
//   * DITAMBAHKAN on-chip: message schedule (16-word ring), ROM konstanta K,
//     FSM 64 ronde, dan feed-forward. Pada baseline semua ini dikerjakan host
//     lewat bus 8-bit dan seluruh state internal dapat dibaca dari luar,
//     sehingga tidak layak untuk secure element.
//   * DIHAPUS: jalur baca register internal (A..H, W) ke luar modul.
//
// Antarmuka: berikan init_state (IV atau chaining state) + block 512-bit,
// pulsakan start. done berpulsa 1 cycle saat digest valid.
// Latensi: busy 65 cycle per blok 512-bit (1 load + 64 ronde), done pada
// cycle berikutnya bersamaan dengan feed-forward.
// -----------------------------------------------------------------------------
`default_nettype none

module sha256_core (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [255:0] init_state, // {H0,H1,...,H7}, H0 di bit paling atas
    input  wire [511:0] block,      // {W0,...,W15}, W0 di bit paling atas
    output reg          busy,
    output reg          done,
    output reg  [255:0] digest
);

  // ---------------- ROM konstanta K ----------------
  function [31:0] k_rom;
    input [5:0] i;
    begin
      case (i)
        6'd0:  k_rom = 32'h428a2f98; 6'd1:  k_rom = 32'h71374491;
        6'd2:  k_rom = 32'hb5c0fbcf; 6'd3:  k_rom = 32'he9b5dba5;
        6'd4:  k_rom = 32'h3956c25b; 6'd5:  k_rom = 32'h59f111f1;
        6'd6:  k_rom = 32'h923f82a4; 6'd7:  k_rom = 32'hab1c5ed5;
        6'd8:  k_rom = 32'hd807aa98; 6'd9:  k_rom = 32'h12835b01;
        6'd10: k_rom = 32'h243185be; 6'd11: k_rom = 32'h550c7dc3;
        6'd12: k_rom = 32'h72be5d74; 6'd13: k_rom = 32'h80deb1fe;
        6'd14: k_rom = 32'h9bdc06a7; 6'd15: k_rom = 32'hc19bf174;
        6'd16: k_rom = 32'he49b69c1; 6'd17: k_rom = 32'hefbe4786;
        6'd18: k_rom = 32'h0fc19dc6; 6'd19: k_rom = 32'h240ca1cc;
        6'd20: k_rom = 32'h2de92c6f; 6'd21: k_rom = 32'h4a7484aa;
        6'd22: k_rom = 32'h5cb0a9dc; 6'd23: k_rom = 32'h76f988da;
        6'd24: k_rom = 32'h983e5152; 6'd25: k_rom = 32'ha831c66d;
        6'd26: k_rom = 32'hb00327c8; 6'd27: k_rom = 32'hbf597fc7;
        6'd28: k_rom = 32'hc6e00bf3; 6'd29: k_rom = 32'hd5a79147;
        6'd30: k_rom = 32'h06ca6351; 6'd31: k_rom = 32'h14292967;
        6'd32: k_rom = 32'h27b70a85; 6'd33: k_rom = 32'h2e1b2138;
        6'd34: k_rom = 32'h4d2c6dfc; 6'd35: k_rom = 32'h53380d13;
        6'd36: k_rom = 32'h650a7354; 6'd37: k_rom = 32'h766a0abb;
        6'd38: k_rom = 32'h81c2c92e; 6'd39: k_rom = 32'h92722c85;
        6'd40: k_rom = 32'ha2bfe8a1; 6'd41: k_rom = 32'ha81a664b;
        6'd42: k_rom = 32'hc24b8b70; 6'd43: k_rom = 32'hc76c51a3;
        6'd44: k_rom = 32'hd192e819; 6'd45: k_rom = 32'hd6990624;
        6'd46: k_rom = 32'hf40e3585; 6'd47: k_rom = 32'h106aa070;
        6'd48: k_rom = 32'h19a4c116; 6'd49: k_rom = 32'h1e376c08;
        6'd50: k_rom = 32'h2748774c; 6'd51: k_rom = 32'h34b0bcb5;
        6'd52: k_rom = 32'h391c0cb3; 6'd53: k_rom = 32'h4ed8aa4a;
        6'd54: k_rom = 32'h5b9cca4f; 6'd55: k_rom = 32'h682e6ff3;
        6'd56: k_rom = 32'h748f82ee; 6'd57: k_rom = 32'h78a5636f;
        6'd58: k_rom = 32'h84c87814; 6'd59: k_rom = 32'h8cc70208;
        6'd60: k_rom = 32'h90befffa; 6'd61: k_rom = 32'ha4506ceb;
        6'd62: k_rom = 32'hbef9a3f7; default: k_rom = 32'hc67178f2;
      endcase
    end
  endfunction

  // ---------------- state kerja ----------------
  reg [31:0] a, b, c, d, e, f, g, h;
  reg [31:0] w [0:15];
  reg [5:0]  rnd;
  reg        finish;          // fase feed-forward
  reg [255:0] h_save;         // chaining value untuk feed-forward

  // ---------------- fungsi ronde: sha256_round (turunan baseline TT07) -------
  wire [255:0] st_next;
  sha256_round u_round (
    .st_in({a,b,c,d,e,f,g,h}), .w(w[0]), .k(k_rom(rnd)), .st_out(st_next)
  );

  // ---------------- message schedule (tambahan) ----------------
  wire [31:0] w1  = w[1];
  wire [31:0] w14 = w[14];
  wire [31:0] sig0 = {w1[6:0],w1[31:7]}    ^ {w1[17:0],w1[31:18]}  ^ (w1 >> 3);
  wire [31:0] sig1 = {w14[16:0],w14[31:17]} ^ {w14[18:0],w14[31:19]} ^ (w14 >> 10);
  wire [31:0] w_next = sig1 + w[9] + sig0 + w[0];

  integer i;

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      busy <= 1'b0; done <= 1'b0; finish <= 1'b0; rnd <= 6'd0;
      digest <= 256'd0; h_save <= 256'd0;
      a <= 0; b <= 0; c <= 0; d <= 0; e <= 0; f <= 0; g <= 0; h <= 0;
      for (i = 0; i < 16; i = i + 1) w[i] <= 32'd0;
    end else begin
      done <= 1'b0;
      if (!busy) begin
        if (start) begin
          busy   <= 1'b1;
          finish <= 1'b0;
          rnd    <= 6'd0;
          h_save <= init_state;
          {a,b,c,d,e,f,g,h} <= init_state;
          for (i = 0; i < 16; i = i + 1)
            w[i] <= block[511 - 32*i -: 32];
        end
      end else if (finish) begin
        // feed-forward: H_i += working variable
        digest <= { h_save[255:224] + a, h_save[223:192] + b,
                    h_save[191:160] + c, h_save[159:128] + d,
                    h_save[127:96]  + e, h_save[95:64]   + f,
                    h_save[63:32]   + g, h_save[31:0]    + h };
        busy   <= 1'b0;
        finish <= 1'b0;
        done   <= 1'b1;
      end else begin
        // satu ronde kompresi
        {a,b,c,d,e,f,g,h} <= st_next;
        for (i = 0; i < 15; i = i + 1) w[i] <= w[i+1];
        w[15] <= w_next;
        if (rnd == 6'd63) finish <= 1'b1;
        rnd <= rnd + 6'd1;
      end
    end
  end

endmodule
`default_nettype wire
