// SPDX-License-Identifier: Apache-2.0
// key_vault.v - penyimpanan kunci master write-once, hierarki kunci, zeroize.
//
// Hierarki kunci (semua diturunkan DI DALAM chip):
//   K_master  : diisi sekali saat provisioning, dihapus setelah LOCK
//   K_tok     = HMAC(K_master, "PERURI-TOKEN-KEY-v1")      -> kunci verdict token
//   K_client  = HMAC(K_master, "PERURI-CLIENT-KEY-v1"||id) -> kunci tiap klien
//               (diturunkan per transaksi oleh screener_top, di-cache)
// Backend cukup memegang K_tok untuk memverifikasi token/log, klien hanya
// memegang K_client miliknya; tidak ada pihak luar yang memerlukan K_master.
//
// Siklus hidup:
//   EMPTY   : kunci master dapat ditulis (provisioning di fasilitas aman)
//   LOCKING : L0 precompute(K_master) -> L1 K_tok = HMAC(K_master, TOK)
//             -> L2 precompute(K_tok)                         (7 blok SHA-256)
//   LOCKED  : hanya state turunan (ipad/opad master & token) yang tersimpan;
//             kunci mentah dihapus
//   TAMPER  : semua material kunci di-zeroize, chip fail-closed (semua REJECT)
// Properti keamanan:
//   * TIDAK ada port baca kunci / state turunan ke bus host
//   * percobaan menulis kunci/kebijakan setelah LOCKED => TAMPER (zeroize)
//   * pin tamper eksternal (aktif rendah) => TAMPER
//   * TAMPER bersifat sticky sampai reset daya (prototipe; ASIC: permanen)

`default_nettype none

module key_vault (
    input  wire         clk,
    input  wire         rst_n,
    // provisioning
    input  wire         key_we,
    input  wire [2:0]   key_idx,
    input  wire [31:0]  key_wdata,
    input  wire         lock_req,
    input  wire         illegal_write,   // tulis ke area kebijakan setelah lock
    input  wire         tamper_n,        // pin tamper eksternal, aktif rendah
    // permintaan ke hmac_engine selama LOCKING
    output reg          eng_start,
    output reg          eng_mode,        // 1 = PRECOMP, 0 = MAC
    output reg  [511:0] eng_msg,
    input  wire         eng_done,
    input  wire [255:0] eng_mac,
    input  wire [255:0] eng_st_i,
    input  wire [255:0] eng_st_o,
    output wire         active,          // vault sedang memakai hmac_engine
    // state turunan (hanya ke hmac_engine / screener_top, tidak ke bus)
    output reg  [255:0] ipad_state,      // master
    output reg  [255:0] opad_state,
    output reg  [255:0] tok_ipad,        // kunci token
    output reg  [255:0] tok_opad,
    // status
    output reg          locked,
    output reg          tamper,
    output wire         ready
);
  localparam [511:0] MSG_TOK = {"PERURI-TOKEN-KEY-v1", 360'd0};

  reg [255:0] key;
  reg [1:0]   ph;        // 0 idle, 1 L0, 2 L1, 3 L2
  reg         wait_eng;

  assign active = (ph != 2'd0);
  assign ready  = locked & ~tamper;

  // sinkronisasi pin tamper (2 flop)
  reg [1:0] tamper_sync;
  always @(posedge clk or negedge rst_n)
    if (!rst_n) tamper_sync <= 2'b11;
    else        tamper_sync <= {tamper_sync[0], tamper_n};
  wire tamper_pin = ~tamper_sync[1];

  wire tamper_event = tamper_pin
                    | (key_we   & (locked | active))
                    | (lock_req & (locked | active))
                    | illegal_write;

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      key <= 256'd0; ipad_state <= 256'd0; opad_state <= 256'd0;
      tok_ipad <= 256'd0; tok_opad <= 256'd0;
      locked <= 1'b0; tamper <= 1'b0; ph <= 2'd0; wait_eng <= 1'b0;
      eng_start <= 1'b0; eng_mode <= 1'b0; eng_msg <= 512'd0;
    end else begin
      eng_start <= 1'b0;
      if (tamper || tamper_event) begin
        // ZEROIZE
        tamper <= 1'b1; locked <= 1'b0; ph <= 2'd0; wait_eng <= 1'b0;
        key <= 256'd0; ipad_state <= 256'd0; opad_state <= 256'd0;
        tok_ipad <= 256'd0; tok_opad <= 256'd0; eng_msg <= 512'd0;
      end else begin
        case (ph)
          2'd0: if (!locked) begin
            if (key_we) begin
              case (key_idx)
                3'd0: key[255:224] <= key_wdata; 3'd1: key[223:192] <= key_wdata;
                3'd2: key[191:160] <= key_wdata; 3'd3: key[159:128] <= key_wdata;
                3'd4: key[127:96]  <= key_wdata; 3'd5: key[95:64]   <= key_wdata;
                3'd6: key[63:32]   <= key_wdata; default: key[31:0] <= key_wdata;
              endcase
            end else if (lock_req) begin
              // L0: precompute K_master
              ph <= 2'd1; eng_mode <= 1'b1; eng_msg <= {key, 256'd0};
              eng_start <= 1'b1; wait_eng <= 1'b1;
            end
          end
          2'd1: if (wait_eng && eng_done) begin
            ipad_state <= eng_st_i; opad_state <= eng_st_o;
            key <= 256'd0;                       // kunci mentah dihapus
            // L1: K_tok = HMAC(K_master, MSG_TOK)  (state master dipakai engine)
            ph <= 2'd2; eng_mode <= 1'b0; eng_msg <= MSG_TOK; eng_start <= 1'b1;
          end
          2'd2: if (wait_eng && eng_done) begin
            // L2: precompute K_tok
            ph <= 2'd3; eng_mode <= 1'b1; eng_msg <= {eng_mac, 256'd0}; eng_start <= 1'b1;
          end
          default: if (wait_eng && eng_done) begin
            tok_ipad <= eng_st_i; tok_opad <= eng_st_o;
            eng_msg <= 512'd0;                   // hapus salinan K_tok
            ph <= 2'd0; wait_eng <= 1'b0; locked <= 1'b1;
          end
        endcase
      end
    end
  end
endmodule

`default_nettype wire
