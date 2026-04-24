#include "tcp_dcs_serializer.h"
#include <cstdio>
#include <cstring>
#include <algorithm>

// ── 追加宏（与 http_dcs_serializer 风格一致）─────────────

#define APPEND_U8(val) do { \
    pos += snprintf(buf+pos, buf_size-pos, \
                    "%u", (unsigned)(val)); \
    if (pos < buf_size) buf[pos++] = '\t'; \
} while(0)

#define APPEND_U16(val) do { \
    pos += snprintf(buf+pos, buf_size-pos, \
                    "%u", (unsigned)(val)); \
    if (pos < buf_size) buf[pos++] = '\t'; \
} while(0)

#define APPEND_U32(val) do { \
    pos += snprintf(buf+pos, buf_size-pos, \
                    "%u", (uint32_t)(val)); \
    if (pos < buf_size) buf[pos++] = '\t'; \
} while(0)

#define APPEND_U64(val) do { \
    pos += snprintf(buf+pos, buf_size-pos, \
                    "%lu", (uint64_t)(val)); \
    if (pos < buf_size) buf[pos++] = '\t'; \
} while(0)

#define APPEND_DBL(val) do { \
    pos += snprintf(buf+pos, buf_size-pos, \
                    "%.6f", (double)(val)); \
    if (pos < buf_size) buf[pos++] = '\t'; \
} while(0)

// 字符串字段：有内容则输出，空则输出空（不输出NONE）
// 用于 host_name（空时为两个连续Tab）
#define APPEND_STR_EMPTY(str) do { \
    if ((str) && (str)[0] != '\0') { \
        size_t _slen = strlen(str); \
        size_t _copy = std::min(_slen, buf_size - pos - 1); \
        memcpy(buf+pos, str, _copy); \
        pos += _copy; \
    } \
    if (pos < buf_size) buf[pos++] = '\t'; \
} while(0)

// 字符串字段：空时输出 NONE（用于 user_account）
#define APPEND_STR_NONE(str) do { \
    const char* _s = ((str) && (str)[0] != '\0') \
                   ? (str) : "NONE"; \
    size_t _slen = strlen(_s); \
    size_t _copy = std::min(_slen, buf_size - pos - 1); \
    memcpy(buf+pos, _s, _copy); \
    pos += _copy; \
    if (pos < buf_size) buf[pos++] = '\t'; \
} while(0)

// 最后一个字段（不加Tab）
#define APPEND_U32_LAST(val) do { \
    pos += snprintf(buf+pos, buf_size-pos, \
                    "%u", (uint32_t)(val)); \
} while(0)

// ─────────────────────────────────────────────────────────
// 序列化主函数
// 字段顺序严格按照协议定义的1~39
// ─────────────────────────────────────────────────────────
size_t TcpDcsSerializer::serialize(const TcpSessionRecord& r,
                                    char*  buf,
                                    size_t buf_size)
{
    size_t pos = 0;

    // ── 1~3 时间 ──────────────────────────────────────────
    APPEND_U32 (r.hour_round_time);      // 1
    APPEND_U32 (r.min_round_time);       // 2
    APPEND_DBL (r.start_time);           // 3

    // ── 4~8 用户标识 ──────────────────────────────────────
    APPEND_STR_NONE(r.user_account);     // 4 空→NONE
    APPEND_U64 (r.user_mac_addr);        // 5
    APPEND_U64 (r.bras_mac_addr);        // 6
    APPEND_U32 (r.user_ip);              // 7
    APPEND_U32 (r.server_ip);            // 8

    // ── 9~10 域名 ─────────────────────────────────────────
    APPEND_U32 (r.host_hash);            // 9
    APPEND_STR_EMPTY(r.host_name);       // 10 空→空字符串（两个Tab）

    // ── 11~12 端口 ────────────────────────────────────────
    APPEND_U16 (r.user_port);            // 11
    APPEND_U16 (r.server_port);          // 12

    // ── 13~16 状态与时长 ──────────────────────────────────
    APPEND_U8  (r.handshake_status);     // 13
    APPEND_U8  (r.socket_status);        // 14
    APPEND_U8  (r.traffic_type);         // 15
    APPEND_U32 (r.duration);             // 16

    // ── 17~18 流量 ────────────────────────────────────────
    APPEND_U32 (r.ul_traffic);           // 17
    APPEND_U32 (r.dl_traffic);           // 18

    // ── 19~24 RTT/抖动 ────────────────────────────────────
    APPEND_U32 (r.user_rtt_count);       // 19
    APPEND_U32 (r.user_rtt_sum);         // 20
    APPEND_U16 (r.server_rtt_count);     // 21
    APPEND_U32 (r.server_rtt_sum);       // 22
    APPEND_U32 (r.user_jitter_sum);      // 23
    APPEND_U32 (r.server_jitter_sum);    // 24

    // ── 25~28 丢包/包计数 ─────────────────────────────────
    APPEND_U32 (r.server_loss);          // 25
    APPEND_U32 (r.user_loss);            // 26
    APPEND_U32 (r.ul_packets);           // 27
    APPEND_U32 (r.dl_packets);           // 28

    // ── 29~32 发起方/握手RTT ──────────────────────────────
    APPEND_U8  (r.user_launch);          // 29
    APPEND_U32 (r.dl_repeat_packets);    // 30
    APPEND_U16 (r.hs_user_rtt);          // 31
    APPEND_U16 (r.hs_server_rtt);        // 32

    // ── 33~37 有效会话 ────────────────────────────────────
    APPEND_U32 (r.eff_duration);         // 33
    APPEND_U32 (r.eff_ul_traffic);       // 34
    APPEND_U32 (r.eff_dl_traffic);       // 35
    APPEND_U32 (r.eff_ul_packets);       // 36
    APPEND_U32 (r.eff_dl_packets);       // 37

    // ── 38~39 乱序（最后一个字段不加Tab）─────────────────
    APPEND_U32 (r.uplink_disorder_cnt);  // 38
    APPEND_U32_LAST(r.downlink_disorder_cnt); // 39

    return pos;
}
