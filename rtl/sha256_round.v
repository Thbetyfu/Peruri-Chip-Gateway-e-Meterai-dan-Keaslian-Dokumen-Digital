// SPDX-License-Identifier: Apache-2.0
// sha256_round.v - satu ronde kompresi SHA-256 (kombinasional).
//
// Diturunkan dari datapath ronde Tiny Tapeout 7 "tiny sha256"
// (tt_um_xeniarose_sha256, (c) 2024 xenia dragon, Apache-2.0).
// Persamaan s0/s1/ch/maj/temp1/temp2 identik dengan baseline; perbedaannya,
// di sini ronde dipisah menjadi modul murni agar dapat dipakai oleh
// sha256_core yang memiliki K-ROM dan message schedule on-chip.

`default_nettype none

module sha256_round (
    input  wire [255:0] st_in,   // {a,b,c,d,e,f,g,h}, a di bit [255:224]
    input  wire [31:0]  w,       // W_t
    input  wire [31:0]  k,       // K_t
    output wire [255:0] st_out
);
  wire [31:0] a = st_in[255:224];
  wire [31:0] b = st_in[223:192];
  wire [31:0] c = st_in[191:160];
  wire [31:0] d = st_in[159:128];
  wire [31:0] e = st_in[127:96];
  wire [31:0] f = st_in[95:64];
  wire [31:0] g = st_in[63:32];
  wire [31:0] h = st_in[31:0];

  wire [31:0] s1    = {e[5:0],e[31:6]} ^ {e[10:0],e[31:11]} ^ {e[24:0],e[31:25]};
  wire [31:0] ch    = (e & f) ^ ((~e) & g);
  wire [31:0] temp1 = h + s1 + ch + k + w;
  wire [31:0] s0    = {a[1:0],a[31:2]} ^ {a[12:0],a[31:13]} ^ {a[21:0],a[31:22]};
  wire [31:0] maj   = (a & b) ^ (a & c) ^ (b & c);
  wire [31:0] temp2 = s0 + maj;

  assign st_out = {temp1 + temp2, a, b, c, d + temp1, e, f, g};
endmodule

`default_nettype wire
