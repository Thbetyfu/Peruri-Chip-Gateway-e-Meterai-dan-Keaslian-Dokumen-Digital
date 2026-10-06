// SPDX-License-Identifier: Apache-2.0
// screener_top.v - Integrity-Gated Transaction Screener (Secure Element Co-Processor)
//
// Antarmuka host: slave memory-mapped 32-bit gaya Avalon-MM (dapat langsung
// dipasang ke HPS-to-FPGA lightweight bridge DE10-Nano, atau ke uart_bridge).
// readdata valid 1 cycle setelah read.
//
// Peta register (alamat WORD):
//   0x00-0x0F  W  TXN[0..15]   rekaman transaksi 64 byte (big-endian word)
//   0x10-0x17  W  TAG[0..7]    HMAC-SHA256 rekaman dari klien resmi
//   0x18       W  CTRL         bit0 = submit
//   0x19       R  STATUS       bit0 busy, bit1 done, bit2 locked, bit3 tamper
//   0x1A       R  RESULT       [1:0] verdict, [23:8] reasons
//   0x1B       R  RESULT_SEQ   nomor urut entri log untuk transaksi terakhir
//   0x1C       R  CYCLES       jumlah cycle pemrosesan transaksi terakhir
//   0x20-0x27  R  TOKEN[0..7]  verdict token bertanda tangan (= mata rantai log)
//   0x28-0x2F  R  HEAD[0..7]   kepala rantai log
//   0x30       R  LOG_COUNT
//   0x31       W  LOG_IDX      pilih entri log untuk dibaca
//   0x32       R  LOG_SEQ      0x33 R LOG_META     0x38-0x3F R LOG_TOKEN[0..7]
//   0x40-0x47  W  KEY[0..7]    hanya sebelum LOCK (tanpa port baca!)
//   0x48       RW CFG_WINDOW   0x49 RW CFG_VEL_LIMIT
//   0x4A       RW CFG_AMT_HI   0x4B RW CFG_AMT_LO   (tulis hanya sebelum LOCK)
//   0x4F       W  LOCK         tulis 0x4C4F434B ("LOCK")
// Setiap tulis ke 0x40-0x4F setelah LOCK => TAMPER + zeroize.
//
// Verdict : 0 ACCEPT, 1 FLAG, 2 ESCALATE, 3 REJECT
// Reasons : b0 INTEGRITY, b1 REPLAY, b2 VELOCITY, b3 AMOUNT, b4 DOMAIN, b5 VAULT
//
// Format rekaman transaksi (byte 0 = paling kiri):
//   [0] domain=0x01 [1] tipe [2:3] id klien [4:7] timestamp [8:15] nonce
//   [16:23] id akun [24:31] nominal [32:63] hash dokumen (SHA-256)
// Kunci: tag transaksi = HMAC(K_client(id), rekaman), dengan
//   K_client = HMAC(K_master, "PERURI-CLIENT-KEY-v1" || id) diturunkan di chip
//   (cache 1 entri). Token = HMAC(K_tok, pesan token), K_tok diturunkan saat LOCK.
// Pesan token (64 byte):
//   [0] domain=0x02 [1] verdict [2:3] reasons [4:7] seq
//   [8:31] 24 byte pertama TAG transaksi [32:63] token sebelumnya (prev head)

`default_nettype none

module screener_top #(
    parameter RULE_IDX_BITS = 6,
    parameter LOG_DEPTH_BITS = 8
) (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        tamper_n,
    // bus host
    input  wire [7:0]  address,
    input  wire        write,
    input  wire [31:0] writedata,
    input  wire        read,
    output reg  [31:0] readdata,
    // status untuk LED / interrupt
    output wire        irq_done,
    output wire        st_locked,
    output wire        st_tamper,
    output wire [1:0]  st_verdict
);
  localparam [7:0] DOM_TXN = 8'h01, DOM_TOKEN = 8'h02;
  localparam [1:0] V_ACCEPT = 2'd0, V_FLAG = 2'd1, V_ESC = 2'd2, V_REJECT = 2'd3;
  localparam [31:0] LOCK_MAGIC = 32'h4C4F434B;

  // ------------------------------------------------------------------ regs
  reg [511:0] txn;
  reg [255:0] tag;
  reg [31:0]  cfg_window, cfg_amt_hi, cfg_amt_lo;
  reg [15:0]  cfg_vel;
  reg [LOG_DEPTH_BITS-1:0] log_idx;

  reg [1:0]   verdict;
  reg [15:0]  reasons;
  reg [31:0]  res_seq, cycles, cyc_cnt;
  reg [255:0] token;
  reg         busy, done_flag;

  wire wr_txn  = write && (address[7:4] == 4'h0);
  wire wr_tag  = write && (address[7:3] == 5'b00010);
  wire wr_ctrl = write && (address == 8'h18);
  wire wr_key  = write && (address[7:3] == 5'b01000);
  wire wr_cfg  = write && (address >= 8'h48) && (address <= 8'h4B);
  wire wr_lock = write && (address == 8'h4F) && (writedata == LOCK_MAGIC);
  wire wr_prov_area = write && (address[7:4] == 4'h4);

  // ------------------------------------------------------------ key vault
  wire        v_active, v_locked, v_tamper, v_ready;
  wire        v_start, v_mode;
  wire [511:0] v_msg;
  wire [255:0] v_ipad, v_opad, v_tipad, v_topad;
  wire        h_busy, h_done;
  wire [255:0] h_mac, h_st_i, h_st_o;

  key_vault u_vault (
    .clk(clk), .rst_n(rst_n),
    .key_we(wr_key), .key_idx(address[2:0]), .key_wdata(writedata),
    .lock_req(wr_lock),
    .illegal_write(wr_prov_area && (v_locked || v_active) && !wr_key && !wr_lock),
    .tamper_n(tamper_n),
    .eng_start(v_start), .eng_mode(v_mode), .eng_msg(v_msg),
    .eng_done(h_done), .eng_mac(h_mac), .eng_st_i(h_st_i), .eng_st_o(h_st_o),
    .active(v_active),
    .ipad_state(v_ipad), .opad_state(v_opad), .tok_ipad(v_tipad), .tok_opad(v_topad),
    .locked(v_locked), .tamper(v_tamper), .ready(v_ready)
  );

  // ----------------------------------------------- cache kunci klien (1 entri)
  // Hanya state ipad/opad K_client yang disimpan; tidak ada jalur ke bus.
  reg  [255:0] c_ipad, c_opad;
  reg  [15:0]  c_id;
  reg          c_valid;
  wire [15:0]  txn_cid  = txn[495:480];
  wire         c_hit    = c_valid && (c_id == txn_cid);
  localparam [495:0] MSG_CLK_HI = {"PERURI-CLIENT-KEY-v1", 336'd0};

  // ----------------------------------------------------------- hmac engine
  // Pemakai: vault (saat LOCK) atau FSM utama. Sel_state memilih pasangan
  // ipad/opad: 0 = master, 1 = klien (cache), 2 = token.
  reg         m_start, m_mode;
  reg [511:0] m_msg;
  reg [1:0]   m_sel;
  wire [255:0] sel_i = v_active ? v_ipad :
                       (m_sel == 2'd1) ? c_ipad : (m_sel == 2'd2) ? v_tipad : v_ipad;
  wire [255:0] sel_o = v_active ? v_opad :
                       (m_sel == 2'd1) ? c_opad : (m_sel == 2'd2) ? v_topad : v_opad;
  hmac_engine u_hmac (
    .clk(clk), .rst_n(rst_n),
    .start(v_active ? v_start : m_start),
    .mode_precomp(v_active ? v_mode : m_mode),
    .msg(v_active ? v_msg : m_msg),
    .ipad_state(sel_i), .opad_state(sel_o),
    .busy(h_busy), .done(h_done),
    .mac_out(h_mac), .pc_st_i(h_st_i), .pc_st_o(h_st_o)
  );

  // ----------------------------------------------------------- rule engine
  reg  r_start;
  wire r_done, r_replay, r_vel, r_amt;
  rule_engine #(.IDX_BITS(RULE_IDX_BITS)) u_rule (
    .clk(clk), .rst_n(rst_n), .start(r_start),
    .account(txn[383:320]), .nonce(txn[447:384]),
    .amount(txn[319:256]),  .tstamp(txn[479:448]),
    .cfg_window(cfg_window), .cfg_vel_limit(cfg_vel),
    .cfg_amount_limit({cfg_amt_hi, cfg_amt_lo}),
    .done(r_done), .replay(r_replay), .velocity(r_vel), .over_amount(r_amt)
  );

  // ------------------------------------------------------------- audit log
  reg  l_append;
  wire [31:0]  l_count, l_rd_seq, l_rd_meta;
  wire [255:0] l_head, l_rd_token;
  audit_log #(.DEPTH_BITS(LOG_DEPTH_BITS)) u_log (
    .clk(clk), .rst_n(rst_n), .append(l_append),
    .verdict({6'd0, verdict}), .reasons(reasons), .token(token),
    .count(l_count), .head(l_head),
    .rd_idx(log_idx), .rd_seq(l_rd_seq), .rd_meta(l_rd_meta), .rd_token(l_rd_token)
  );

  // ------------------------------------------------------------------ FSM
  localparam [2:0] S_IDLE = 3'd0, S_MAC = 3'd1, S_RULE = 3'd2,
                   S_SIGN = 3'd3, S_LOG = 3'd4, S_KD1 = 3'd5, S_KD2 = 3'd6;
  reg [2:0] state;

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state <= S_IDLE; busy <= 1'b0; done_flag <= 1'b0;
      txn <= 512'd0; tag <= 256'd0;
      cfg_window <= 32'd60; cfg_vel <= 16'd5;
      cfg_amt_hi <= 32'd0;  cfg_amt_lo <= 32'd10_000_000;
      log_idx <= {LOG_DEPTH_BITS{1'b0}};
      verdict <= V_REJECT; reasons <= 16'd0; res_seq <= 32'd0;
      cycles <= 32'd0; cyc_cnt <= 32'd0; token <= 256'd0;
      m_start <= 1'b0; m_mode <= 1'b0; m_sel <= 2'd0; m_msg <= 512'd0;
      r_start <= 1'b0; l_append <= 1'b0;
      c_ipad <= 256'd0; c_opad <= 256'd0; c_id <= 16'd0; c_valid <= 1'b0;
    end else begin
      m_start <= 1'b0; r_start <= 1'b0; l_append <= 1'b0;

      // ---- tulis register (input dikunci selama busy)
      if (!busy) begin
        if (wr_txn) case (address[3:0])
          4'd0:  txn[511:480] <= writedata; 4'd1:  txn[479:448] <= writedata;
          4'd2:  txn[447:416] <= writedata; 4'd3:  txn[415:384] <= writedata;
          4'd4:  txn[383:352] <= writedata; 4'd5:  txn[351:320] <= writedata;
          4'd6:  txn[319:288] <= writedata; 4'd7:  txn[287:256] <= writedata;
          4'd8:  txn[255:224] <= writedata; 4'd9:  txn[223:192] <= writedata;
          4'd10: txn[191:160] <= writedata; 4'd11: txn[159:128] <= writedata;
          4'd12: txn[127:96]  <= writedata; 4'd13: txn[95:64]   <= writedata;
          4'd14: txn[63:32]   <= writedata; default: txn[31:0]  <= writedata;
        endcase
        if (wr_tag) case (address[2:0])
          3'd0: tag[255:224] <= writedata; 3'd1: tag[223:192] <= writedata;
          3'd2: tag[191:160] <= writedata; 3'd3: tag[159:128] <= writedata;
          3'd4: tag[127:96]  <= writedata; 3'd5: tag[95:64]   <= writedata;
          3'd6: tag[63:32]   <= writedata; default: tag[31:0] <= writedata;
        endcase
      end
      if (wr_cfg && !v_locked && !v_active && !v_tamper) case (address[1:0])
        2'd0: cfg_window <= writedata;
        2'd1: cfg_vel    <= writedata[15:0];
        2'd2: cfg_amt_hi <= writedata;
        default: cfg_amt_lo <= writedata;
      endcase
      if (write && address == 8'h31) log_idx <= writedata[LOG_DEPTH_BITS-1:0];

      if (busy) cyc_cnt <= cyc_cnt + 32'd1;

      case (state)
        S_IDLE: if (wr_ctrl && writedata[0] && !h_busy) begin
          done_flag <= 1'b0; cyc_cnt <= 32'd1; busy <= 1'b1;
          if (!v_ready) begin
            // fail-closed: tanpa kunci tidak ada token yang dapat diterbitkan
            verdict <= V_REJECT; reasons <= 16'h0020; token <= 256'd0;
            res_seq <= 32'hFFFF_FFFF; cycles <= 32'd1;
            busy <= 1'b0; done_flag <= 1'b1;
          end else if (c_hit) begin
            m_msg <= txn; m_mode <= 1'b0; m_sel <= 2'd1; m_start <= 1'b1; state <= S_MAC;
          end else begin
            // turunkan K_client = HMAC(K_master, MSG_CLK || id)
            c_valid <= 1'b0;
            m_msg <= {MSG_CLK_HI, txn_cid}; m_mode <= 1'b0; m_sel <= 2'd0;
            m_start <= 1'b1; state <= S_KD1;
          end
        end

        S_KD1: if (h_done) begin
          // precompute K_client
          m_msg <= {h_mac, 256'd0}; m_mode <= 1'b1; m_start <= 1'b1; state <= S_KD2;
        end

        S_KD2: if (h_done) begin
          c_ipad <= h_st_i; c_opad <= h_st_o; c_id <= txn_cid; c_valid <= 1'b1;
          m_msg <= txn; m_mode <= 1'b0; m_sel <= 2'd1; m_start <= 1'b1; state <= S_MAC;
        end

        // ---- Integrity Gate: HMAC rekaman dibandingkan dengan TAG
        S_MAC: if (h_done) begin
          if (txn[511:504] != DOM_TXN || h_mac != tag) begin
            verdict <= V_REJECT;
            reasons <= {11'd0, (txn[511:504] != DOM_TXN), 3'b000, (h_mac != tag)};
            state   <= S_SIGN;     // ditolak: TIDAK mencapai rule engine
          end else begin
            r_start <= 1'b1; state <= S_RULE;
          end
        end

        // ---- Rule Engine + Decision Unit
        S_RULE: if (r_done) begin
          reasons <= {12'd0, r_amt, r_vel, r_replay, 1'b0};
          if      (r_replay) verdict <= V_REJECT;
          else if (r_amt)    verdict <= V_ESC;
          else if (r_vel)    verdict <= V_FLAG;
          else               verdict <= V_ACCEPT;
          state <= S_SIGN;
        end

        // ---- Verdict token = HMAC(K, verdict || seq || tag || prev_head)
        S_SIGN: if (!m_start && !h_busy) begin
          m_msg   <= {DOM_TOKEN, 6'd0, verdict, reasons, l_count, tag[255:64], l_head};
          m_mode  <= 1'b0; m_sel <= 2'd2; m_start <= 1'b1; state <= S_LOG;
        end

        S_LOG: if (h_done) begin
          token    <= h_mac;
          res_seq  <= l_count;
          l_append <= 1'b1;
          cycles   <= cyc_cnt;
          busy <= 1'b0; done_flag <= 1'b1; state <= S_IDLE;
        end

        default: state <= S_IDLE;
      endcase

      if (v_tamper) begin
        c_ipad <= 256'd0; c_opad <= 256'd0; c_valid <= 1'b0;   // zeroize cache klien
      end
      if (v_tamper && busy) begin
        // tamper di tengah proses: batalkan, fail-closed
        verdict <= V_REJECT; reasons <= 16'h0020; token <= 256'd0;
        busy <= 1'b0; done_flag <= 1'b1; state <= S_IDLE;
      end
    end
  end

  // -------------------------------------------------------------- readback
  // CATATAN KEAMANAN: tidak ada cabang yang mengembalikan kunci, ipad/opad,
  // atau state internal SHA. Alamat KEY (0x40-0x47) dan LOCK membaca 0.
  function [31:0] w256;
    input [255:0] v; input [2:0] i;
    begin w256 = v[255 - 32*i -: 32]; end
  endfunction

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) readdata <= 32'd0;
    else if (read) begin
      casez (address)
        8'h19: readdata <= {28'd0, v_tamper, v_locked, done_flag, busy | v_active};
        8'h1A: readdata <= {8'd0, reasons, 6'd0, verdict};
        8'h1B: readdata <= res_seq;
        8'h1C: readdata <= cycles;
        8'b0010_0???: readdata <= w256(token,      address[2:0]);
        8'b0010_1???: readdata <= w256(l_head,     address[2:0]);
        8'h30: readdata <= l_count;
        8'h32: readdata <= l_rd_seq;
        8'h33: readdata <= l_rd_meta;
        8'b0011_1???: readdata <= w256(l_rd_token, address[2:0]);
        8'h48: readdata <= cfg_window;
        8'h49: readdata <= {16'd0, cfg_vel};
        8'h4A: readdata <= cfg_amt_hi;
        8'h4B: readdata <= cfg_amt_lo;
        default: readdata <= 32'd0;
      endcase
    end
  end

  assign irq_done   = done_flag;
  assign st_locked  = v_locked;
  assign st_tamper  = v_tamper;
  assign st_verdict = verdict;
endmodule

`default_nettype wire
