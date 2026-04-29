#pragma once
#include <cstdint>
#include <cstring>

// ─────────────────────────────────────────────────────────
// Ping（ICMP Echo）会话记录（15个字段）
// 对应 raw/ping_YYYYMMDDTHHMMSS.dcs
// ─────────────────────────────────────────────────────────
struct PingRecord {

    // ── 1~4 时间 ──────────────────────────────────────────
    uint32_t hour_round_time = 0;   // 整点小时时间戳(秒)
    uint32_t min_round_time  = 0;   // 整分时间戳(秒)
    double   start_time      = 0.0; // ICMP请求发出时间(秒，微秒精度)
    double   end_time        = 0.0; // ICMP响应到达时间(0=无响应)

    // ── 5~7 用户标识 ──────────────────────────────────────
    uint64_t user_mac_addr   = 0;
    uint64_t bras_mac_addr   = 0;
    char     user_account[256] = {};  // 用户账号（从Radius表查）

    // ── 8~11 地址与域名 ───────────────────────────────────
    uint32_t user_ip         = 0;
    uint32_t server_ip       = 0;
    uint32_t host_hash       = 0;   // 目标域名hash（通常为0，ICMP无DNS）
    char     host_name[256]  = {};  // 目标域名（通常为空）

    // ── 12~15 统计 ──────���─────────────────────────────────
    uint16_t request_count   = 0;   // ICMP请求次数
    uint16_t response_count  = 0;   // ICMP响应次数
    uint32_t total_duration  = 0;   // 所有成功往返时延之和(ms)
    uint16_t payload_size    = 0;   // Ping负载大小(bytes)

    PingRecord() { memset(this, 0, sizeof(*this)); }
};
