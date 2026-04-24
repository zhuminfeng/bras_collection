#pragma once
#include <cstdint>
#include <cstring>

// ─────────────────────────────────────────────────────────
// TCP会话记录（39个字段）
// 对应 raw/tcp_YYYYMMDDTHHMMSS.dcs
// ─────────────────────────────────────────────────────────
struct TcpSessionRecord {

    // ── 1~3 时间 ──────────────────────────────────────────
    uint32_t  hour_round_time  = 0;   // 整点小时时间戳(秒)
    uint32_t  min_round_time   = 0;   // 整分时间戳(秒)
    double    start_time       = 0.0; // 会话开始时间(秒,微秒精度)

    // ── 4~8 用户标识 ──────────────────────────────────────
    char      user_account[256] = {};  // 用户账号
    uint64_t  user_mac_addr    = 0;
    uint64_t  bras_mac_addr    = 0;
    uint32_t  user_ip          = 0;
    uint32_t  server_ip        = 0;

    // ── 9~10 域名（可从DNS/SNI获取）──────────────────────
    uint32_t  host_hash        = 0;
    char      host_name[256]   = {};   // 空串=未知，不输出NONE

    // ── 11~12 端口 ────────────────────────────────────────
    uint16_t  user_port        = 0;
    uint16_t  server_port      = 0;

    // ── 13~16 状态与时长 ──────────────────────────────────
    // handshake_status: 0=成功 1=服务器无响应 2=用户侧无响应
    //                   3=用户侧复位 4=服务器复位 5=解码异常 6=初始
    uint8_t   handshake_status = 6;
    // socket_status: 同上
    uint8_t   socket_status    = 6;
    // traffic_type: 0=未识别 1=游戏 2=视频 3=直播
    uint8_t   traffic_type     = 0;
    uint32_t  duration         = 0;   // ms

    // ── 17~18 流量 ────────────────────────────────────────
    uint32_t  ul_traffic       = 0;   // bytes（含IP/TCP头）
    uint32_t  dl_traffic       = 0;

    // ── 19~24 RTT/抖动 ────────────────────────────────────
    uint32_t  user_rtt_count   = 0;
    uint32_t  user_rtt_sum     = 0;   // ms
    uint16_t  server_rtt_count = 0;
    uint32_t  server_rtt_sum   = 0;   // ms
    uint32_t  user_jitter_sum  = 0;   // ms
    uint32_t  server_jitter_sum= 0;   // ms

    // ── 25~28 丢包/包计数 ─────────────────────────────────
    uint32_t  server_loss      = 0;   // 包数
    uint32_t  user_loss        = 0;
    uint32_t  ul_packets       = 0;
    uint32_t  dl_packets       = 0;

    // ── 29~32 发起方/握手RTT ──────────────────────────────
    uint8_t   user_launch      = 0;   // 1=用户发起 0=外部发起
    uint32_t  dl_repeat_packets= 0;
    uint16_t  hs_user_rtt      = 0;   // ms
    uint16_t  hs_server_rtt    = 0;   // ms

    // ── 33~37 有效会话 ────────────────────────────────────
    uint32_t  eff_duration     = 0;   // ms
    uint32_t  eff_ul_traffic   = 0;   // bytes
    uint32_t  eff_dl_traffic   = 0;
    uint32_t  eff_ul_packets   = 0;
    uint32_t  eff_dl_packets   = 0;

    // ── 38~39 乱序 ────────────────────────────────────────
    uint32_t  uplink_disorder_cnt   = 0;
    uint32_t  downlink_disorder_cnt = 0;

    TcpSessionRecord() {
        memset(this, 0, sizeof(*this));
        handshake_status = 6;
        socket_status    = 6;
    }
};

// ─────────────────────────────────────────────────────────
// Radius DCS 记录（55个字段）
// 对应 raw/radius_YYYYMMDDTHHMMSS.dcs
// ─────────────────────────────────────────────────────────
struct RadiusRecord {

    // ── 1~4 时间 ──────────────────────────────────────────
    uint32_t  hour_round_time  = 0;     // 整点小时时间戳(秒)
    uint32_t  min_round_time   = 0;     // 整分时间戳(秒)
    double    start_time       = 0.0;   // 请求到达时间(微秒精度)
    double    end_time         = 0.0;   // 响应到达时间(0=无响应)

    // ── 5~9 地址与代码 ────────────────────────────────────
    uint32_t  bras_ip          = 0;     // NAS-IP-Address AVP / 包源IP
    uint32_t  radius_server_ip = 0;     // RADIUS服务器IP
    uint64_t  bras_mac         = 0;     // 以太头BRAS MAC
    uint16_t  request_code     = 0;     // Radius请求代码
    uint16_t  reply_code       = 0;     // Radius响应代码(0=无响应)

    // ── 10~16 用户/NAS基础信息 ────────────────────────────
    char      user_name[256]      = {};
    uint32_t  nas_ip              = 0;
    uint32_t  nas_port            = 0;
    uint32_t  service_type        = 0;
    uint32_t  framed_protocol     = 0;
    uint32_t  framed_ip           = 0;  // 分配的用户IP(主机序)
    char      reply_message[256]  = {};

    // ── 17~22 超时与站点标识 ──────────────────────────────
    uint32_t  session_timeout     = 0;  // 秒
    uint32_t  idle_timeout        = 0;  // 秒
    char      calling_station_id[256] = {};  // 用户MAC字符串
    uint64_t  calling_station_id_int  = 0;   // 用户MAC整数
    char      called_station_id[256]  = {};  // BRAS MAC字符串
    char      nas_identifier[256]     = {};

    // ── 23~34 计费 ────────────────────────────────────────
    uint32_t  acct_status_type     = 0; // 1=Start 2=Stop 3=Interim
    uint32_t  acct_delay_time      = 0;
    uint32_t  acct_input_octets    = 0; // 上行流量(bytes)
    uint32_t  acct_output_octets   = 0; // 下行流量(bytes)
    char      acct_session_id[256] = {};
    uint32_t  acct_authen          = 0;
    uint32_t  acct_session_time    = 0; // 秒
    uint32_t  acct_input_packets   = 0;
    uint32_t  acct_output_packets  = 0;
    uint32_t  acct_terminate_cause = 0;
    uint32_t  acct_input_gigawords = 0; // Kbyte
    uint32_t  acct_output_gigawords= 0; // Kbyte

    // ── 35~41 NAS端口与OLT信息 ────────────────────────────
    uint32_t  nas_port_type        = 0;
    char      connect_info[256]    = {};
    char      nas_port_id[256]     = {};
    uint32_t  olt_ip               = 0; // 从nas_port_id解析
    uint16_t  pon_board            = 0; // (frame<<8)|board
    uint16_t  pon_port             = 0;
    char      onu_no[16]           = {}; // 16字符纯HEX→ASCII解码

    // ── 42~46 NAT与带宽 ───────────────────────────────────
    uint32_t  nat_public_ip        = 0;
    uint16_t  nat_start_port       = 0;
    uint16_t  nat_end_port         = 0;
    uint32_t  ul_band_limits       = 0; // Kbps
    uint32_t  dl_band_limits       = 0; // Kbps

    // ── 47~55 IPv6 ────────────────────────────────────────
    uint64_t  framed_ipv6_prefix              = 0;
    uint16_t  ipv6_prefix_length              = 0;
    uint64_t  framed_interface_id             = 0;
    uint64_t  delegated_ipv6_prefix           = 0;
    uint16_t  delegated_ipv6_prefix_length    = 0;
    uint32_t  acct_ipv6_input_octets          = 0;
    uint32_t  acct_ipv6_input_gigawords       = 0;
    uint32_t  acct_ipv6_output_octets         = 0;
    uint32_t  acct_ipv6_output_gigawords      = 0;

    // ── 内部字段（不输出到DCS）────────────────────────────
    uint8_t   radius_id   = 0;   // Radius Identifier（请求/响应匹配用）
    uint32_t  client_ip   = 0;   // 请求方IP（用于匹配key）

    RadiusRecord() { memset(this, 0, sizeof(*this)); }
};

// ─────────────────────────────────────────────────────────
// DNS 记录
// ─────────────────────────────────────────────────────────
struct DnsRecord {
    uint64_t  query_time           = 0;   // 微秒
    uint32_t  user_ip              = 0;
    uint32_t  dns_server_ip        = 0;
    char      query_name[256]      = {};
    uint16_t  query_type           = 0;
    uint8_t   result_code          = 0;
    uint32_t  response_duration_us = 0;
    char      answers[512]         = {};
};

// ─────────────────────────────────────────────────────────
// UDP 流记录
// ─────────────────────────────────────────────────────────
struct UdpStreamRecord {
    uint64_t  start_time      = 0;    // 微秒
    uint32_t  user_ip         = 0;
    uint32_t  server_ip       = 0;
    uint16_t  user_port       = 0;
    uint16_t  server_port     = 0;
    uint32_t  ndpi_app_proto  = 0;
    uint8_t   traffic_type    = 0;
    uint32_t  expected_pkts   = 0;
    uint32_t  received_pkts   = 0;
    float     loss_rate       = 0.0f;
    uint32_t  duration_ms     = 0;
};

// ─────────────────────────────────────────────────────────
// PPPoE 信令记录
// ─────────────────────────────────────────────────────────
struct PPPoERecord {
    uint64_t  event_time     = 0;
    uint8_t   event_type     = 0;
    uint64_t  client_mac     = 0;
    uint64_t  server_mac     = 0;
    uint16_t  session_id     = 0;
    char      ac_name[64]    = {};
    char      service_name[64] = {};
    char      user_account[256]= {};
};
