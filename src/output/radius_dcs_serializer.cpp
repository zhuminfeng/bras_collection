#include "radius_dcs_serializer.h"
#include <cstdio>
#include <cstring>
#include <algorithm>

// ── 追加宏 ───────────────────────────────────────────────

#define APPEND_U16(val) do { \
    pos += snprintf(buf+pos, buf_size-pos, \
                    "%u", (unsigned)(uint16_t)(val)); \
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

// 字符串：有内容则输出，空则输出空字符串（连续Tab）
#define APPEND_STR(str) do { \
    if ((str) && (str)[0] != '\0') { \
        size_t _slen = strlen(str); \
        size_t _copy = std::min(_slen, buf_size - pos - 1); \
        memcpy(buf+pos, (str), _copy); \
        pos += _copy; \
    } \
    if (pos < buf_size) buf[pos++] = '\t'; \
} while(0)

// 最后一个字段（不加Tab，加换行）
#define APPEND_U32_LAST(val) do { \
    pos += snprintf(buf+pos, buf_size-pos, \
                    "%u", (uint32_t)(val)); \
} while(0)

// ─────────────────────────────────────────────────────────
// 序列化主函数（55个字段）
// ─────────────────────────────────────────────────────────
size_t RadiusDcsSerializer::serialize(const RadiusRecord& r,
                                       char*  buf,
                                       size_t buf_size)
{
    size_t pos = 0;

    // ── 1~4 时间 ──────────────────────────────────────────
    APPEND_U32(r.hour_round_time);           //  1
    APPEND_U32(r.min_round_time);            //  2
    APPEND_DBL(r.start_time);               //  3
    APPEND_DBL(r.end_time);                 //  4

    // ── 5~9 地址与代码 ────────────────────────────────────
    APPEND_U32(r.bras_ip);                  //  5
    APPEND_U32(r.radius_server_ip);         //  6
    APPEND_U64(r.bras_mac);                 //  7
    APPEND_U16(r.request_code);             //  8
    APPEND_U16(r.reply_code);               //  9

    // ── 10~16 用户/NAS基础信息 ────────────────────────────
    APPEND_STR(r.user_name);                // 10
    APPEND_U32(r.nas_ip);                   // 11
    APPEND_U32(r.nas_port);                 // 12
    APPEND_U32(r.service_type);             // 13
    APPEND_U32(r.framed_protocol);          // 14
    APPEND_U32(r.framed_ip);               // 15
    APPEND_STR(r.reply_message);            // 16

    // ── 17~22 超时与站点标识 ──────────────────────────────
    APPEND_U32(r.session_timeout);          // 17
    APPEND_U32(r.idle_timeout);             // 18
    APPEND_STR(r.calling_station_id);       // 19
    APPEND_U64(r.calling_station_id_int);   // 20
    APPEND_STR(r.called_station_id);        // 21
    APPEND_STR(r.nas_identifier);           // 22

    // ── 23~34 计费 ────────────────────────────────────────
    APPEND_U32(r.acct_status_type);         // 23
    APPEND_U32(r.acct_delay_time);          // 24
    APPEND_U32(r.acct_input_octets);        // 25
    APPEND_U32(r.acct_output_octets);       // 26
    APPEND_STR(r.acct_session_id);          // 27
    APPEND_U32(r.acct_authen);              // 28
    APPEND_U32(r.acct_session_time);        // 29
    APPEND_U32(r.acct_input_packets);       // 30
    APPEND_U32(r.acct_output_packets);      // 31
    APPEND_U32(r.acct_terminate_cause);     // 32
    APPEND_U32(r.acct_input_gigawords);     // 33
    APPEND_U32(r.acct_output_gigawords);    // 34

    // ── 35~41 NAS端口与OLT信息 ────────────────────────────
    APPEND_U32(r.nas_port_type);            // 35
    APPEND_STR(r.connect_info);             // 36
    APPEND_STR(r.nas_port_id);              // 37
    APPEND_U32(r.olt_ip);                   // 38
    APPEND_U16(r.pon_board);               // 39
    APPEND_U16(r.pon_port);                // 40
    APPEND_STR(r.onu_no);                   // 41

    // ── 42~46 NAT与带宽 ───────────────────────────────────
    APPEND_U32(r.nat_public_ip);            // 42
    APPEND_U16(r.nat_start_port);          // 43
    APPEND_U16(r.nat_end_port);            // 44
    APPEND_U32(r.ul_band_limits);           // 45
    APPEND_U32(r.dl_band_limits);           // 46

    // ── 47~55 IPv6 ────────────────────────────────────────
    APPEND_U64(r.framed_ipv6_prefix);           // 47
    APPEND_U16(r.ipv6_prefix_length);           // 48
    APPEND_U64(r.framed_interface_id);          // 49
    APPEND_U64(r.delegated_ipv6_prefix);        // 50
    APPEND_U16(r.delegated_ipv6_prefix_length); // 51
    APPEND_U32(r.acct_ipv6_input_octets);       // 52
    APPEND_U32(r.acct_ipv6_input_gigawords);    // 53
    APPEND_U32(r.acct_ipv6_output_octets);      // 54
    APPEND_U32_LAST(r.acct_ipv6_output_gigawords); // 55

    return pos;
}
