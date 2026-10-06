// SPDX-License-Identifier: Apache-2.0
// rule_engine.v - Deterministic Rule Engine + Account State Memory
//
// Hanya dijalankan SETELAH Integrity Gate lolos, sehingga rekaman palsu tidak
// pernah dapat mengubah state akun. Seluruh field (akun, nonce, nominal,
// timestamp) berasal dari rekaman yang sudah terautentikasi HMAC, jadi host
// yang dikompromi tidak dapat memalsukan timestamp untuk lolos velocity.
//
// Aturan:
//   REPLAY      : akun dikenal dan nonce <= nonce terakhir  -> tolak
//   VELOCITY    : jumlah transaksi akun dalam jendela waktu > cfg_vel_limit
//   OVER_AMOUNT : nominal > cfg_amount_limit
//
// Account State Memory: tabel direct-mapped 2^IDX_BITS entri (indeks = bit
// bawah ID akun), disimpan di RAM yang dapat di-infer (M10K) + bit valid di
// register. Entri yang tergusur (collision) diperlakukan sebagai akun baru;
// versi ASIC memakai tabel lebih besar / set-associative.
//
// Latensi: 3 cycle (ph1 baca RAM, ph2 evaluasi + tulis, done).

`default_nettype none

module rule_engine #(
    parameter IDX_BITS = 6
) (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        start,
    input  wire [63:0] account,
    input  wire [63:0] nonce,
    input  wire [63:0] amount,
    input  wire [31:0] tstamp,
    input  wire [31:0] cfg_window,
    input  wire [15:0] cfg_vel_limit,
    input  wire [63:0] cfg_amount_limit,
    output reg         done,
    output reg         replay,
    output reg         velocity,
    output reg         over_amount
);
  localparam N = (1 << IDX_BITS);

  // ---------------- account state memory ----------------
  reg [N-1:0]  ent_valid;
  reg [63:0]   mem_acct  [0:N-1];
  reg [63:0]   mem_nonce [0:N-1];
  reg [31:0]   mem_win   [0:N-1];
  reg [15:0]   mem_cnt   [0:N-1];

  wire [IDX_BITS-1:0] idx = account[IDX_BITS-1:0];

  // port baca sinkron (ph1)
  reg [63:0] r_acct, r_nonce;
  reg [31:0] r_win;
  reg [15:0] r_cnt;
  reg        r_valid;

  // port tulis (ph2)
  reg                we;
  reg [IDX_BITS-1:0] wa;
  reg [63:0]         w_acct, w_nonce;
  reg [31:0]         w_win;
  reg [15:0]         w_cnt;

  always @(posedge clk) begin
    if (we) begin
      mem_acct[wa]  <= w_acct;
      mem_nonce[wa] <= w_nonce;
      mem_win[wa]   <= w_win;
      mem_cnt[wa]   <= w_cnt;
    end
    r_acct  <= mem_acct[idx];
    r_nonce <= mem_nonce[idx];
    r_win   <= mem_win[idx];
    r_cnt   <= mem_cnt[idx];
  end

  // ---------------- evaluasi (kombinasional pada ph2) ----------------
  wire        hit      = r_valid && (r_acct == account);
  wire        is_rep   = hit && (nonce <= r_nonce);
  wire [31:0] elapsed  = tstamp - r_win;
  wire        in_win   = hit && (elapsed < cfg_window);
  wire [15:0] new_cnt  = in_win ? ((r_cnt == 16'hFFFF) ? 16'hFFFF : r_cnt + 16'd1) : 16'd1;
  wire [31:0] new_win  = in_win ? r_win : tstamp;

  reg [1:0] ph;

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      ph <= 2'd0; done <= 1'b0;
      replay <= 1'b0; velocity <= 1'b0; over_amount <= 1'b0;
      ent_valid <= {N{1'b0}}; r_valid <= 1'b0;
      we <= 1'b0; wa <= {IDX_BITS{1'b0}};
      w_acct <= 64'd0; w_nonce <= 64'd0; w_win <= 32'd0; w_cnt <= 16'd0;
    end else begin
      done <= 1'b0;
      we   <= 1'b0;
      case (ph)
        2'd0: if (start) begin
          r_valid <= ent_valid[idx];      // RAM dibaca pada edge yang sama
          ph <= 2'd1;
        end
        2'd1: begin
          ph <= 2'd2;                     // data RAM (r_*) valid di ph2
        end
        default: begin
          replay      <= is_rep;
          velocity    <= !is_rep && (new_cnt > cfg_vel_limit);
          over_amount <= !is_rep && (amount  > cfg_amount_limit);
          if (!is_rep) begin
            we <= 1'b1; wa <= idx;
            w_acct <= account; w_nonce <= nonce; w_win <= new_win; w_cnt <= new_cnt;
            ent_valid[idx] <= 1'b1;
          end
          done <= 1'b1;
          ph   <= 2'd0;
        end
      endcase
    end
  end
endmodule

`default_nettype wire
