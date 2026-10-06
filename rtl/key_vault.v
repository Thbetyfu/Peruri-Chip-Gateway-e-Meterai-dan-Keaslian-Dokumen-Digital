// SPDX-License-Identifier: Apache-2.0
// key_vault.v - penyimpanan kunci HMAC write-once dengan zeroize.
//
// Siklus hidup:
//   EMPTY  : kunci dapat ditulis (provisioning di fasilitas aman)
//   LOCKING: precompute ipad/opad berjalan di hmac_engine
//   LOCKED : hanya state turunan (ipad/opad) yang tersimpan; kunci mentah dihapus
//   TAMPER : semua material kunci di-zeroize, chip fail-closed (semua REJECT)
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
    // ke/dari hmac_engine (precompute)
    output reg          pc_start,
    output wire [511:0] pc_keyblock,
    input  wire         pc_done,
    input  wire [255:0] pc_st_i,
    input  wire [255:0] pc_st_o,
    output wire         pc_active,
    // ke hmac_engine (operasi MAC)
    output reg  [255:0] ipad_state,
    output reg  [255:0] opad_state,
    // status
    output reg          locked,
    output reg          tamper,
    output wire         ready
);
  reg [255:0] key;
  reg         locking;

  assign pc_keyblock = {key, 256'd0};      // kunci 32 byte, di-pad nol ke 64 byte
  assign pc_active   = locking;
  assign ready       = locked & ~tamper;

  // sinkronisasi pin tamper (2 flop)
  reg [1:0] tamper_sync;
  always @(posedge clk or negedge rst_n)
    if (!rst_n) tamper_sync <= 2'b11;
    else        tamper_sync <= {tamper_sync[0], tamper_n};
  wire tamper_pin = ~tamper_sync[1];

  wire tamper_event = tamper_pin
                    | (key_we   & (locked | locking))
                    | (lock_req & (locked | locking))
                    | illegal_write;

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      key <= 256'd0; ipad_state <= 256'd0; opad_state <= 256'd0;
      locked <= 1'b0; locking <= 1'b0; tamper <= 1'b0; pc_start <= 1'b0;
    end else begin
      pc_start <= 1'b0;
      if (tamper || tamper_event) begin
        // ZEROIZE
        tamper <= 1'b1; locked <= 1'b0; locking <= 1'b0;
        key <= 256'd0; ipad_state <= 256'd0; opad_state <= 256'd0;
      end else if (!locked && !locking) begin
        if (key_we) begin
          case (key_idx)
            3'd0: key[255:224] <= key_wdata; 3'd1: key[223:192] <= key_wdata;
            3'd2: key[191:160] <= key_wdata; 3'd3: key[159:128] <= key_wdata;
            3'd4: key[127:96]  <= key_wdata; 3'd5: key[95:64]   <= key_wdata;
            3'd6: key[63:32]   <= key_wdata; default: key[31:0] <= key_wdata;
          endcase
        end else if (lock_req) begin
          locking <= 1'b1; pc_start <= 1'b1;
        end
      end else if (locking && pc_done) begin
        ipad_state <= pc_st_i; opad_state <= pc_st_o;
        key <= 256'd0;                 // kunci mentah dihapus setelah precompute
        locking <= 1'b0; locked <= 1'b1;
      end
    end
  end
endmodule

`default_nettype wire
