#include "onu_dcs_serializer.h"
#include <cstdio>
#include <cstring>
#include <algorithm>

// ── 追加宏 ───────────────────────────────────────────────
#define NEED(n) do { if (pos + (n) >= buf_size) return pos; } while(0)

#define APPEND_U8(val) do { \
    NEED(8); \
    pos += snprintf(buf+pos, buf_size-pos, "%u", (unsigned)(uint8_t)(val)); \
    buf[pos++] = '\t'; \
} while(0)

#define APPEND_U16(val) do { \
    NEED(8); \
    pos += snprintf(buf+pos, buf_size-pos, "%u", (unsigned)(uint16_t)(val)); \
    buf[pos++] = '\t'; \
} while(0)

#define APPEND_I16(val) do { \
    NEED(8); \
    pos += snprintf(buf+pos, buf_size-pos, "%d", (int)(int16_t)(val)); \
    buf[pos++] = '\t'; \
} while(0)

#define APPEND_I32(val) do { \
    NEED(16); \
    pos += snprintf(buf+pos, buf_size-pos, "%d", (int)(val)); \
    buf[pos++] = '\t'; \
} while(0)

#define APPEND_U32(val) do { \
    NEED(16); \
    pos += snprintf(buf+pos, buf_size-pos, "%u", (uint32_t)(val)); \
    buf[pos++] = '\t'; \
} while(0)

#define APPEND_U64(val) do { \
    NEED(24); \
    pos += snprintf(buf+pos, buf_size-pos, "%lu", (uint64_t)(val)); \
    buf[pos++] = '\t'; \
} while(0)

#define APPEND_DBL(val) do { \
    NEED(24); \
    pos += snprintf(buf+pos, buf_size-pos, "%.6f", (double)(val)); \
    buf[pos++] = '\t'; \
} while(0)

// 字符串：有内容则输出，空则输出空字符串（两个连续Tab）
#define APPEND_STR(str) do { \
    if ((str) && (str)[0]) { \
        size_t _l = strlen(str); \
        size_t _c = std::min(_l, buf_size - pos - 1); \
        memcpy(buf+pos, (str), _c); \
        pos += _c; \
    } \
    NEED(2); \
    buf[pos++] = '\t'; \
} while(0)

// 字符串：固定输出 NONE（用于占位设备）
#define APPEND_NONE_STR() do { \
    NEED(8); \
    memcpy(buf+pos, "NONE", 4); \
    pos += 4; \
    buf[pos++] = '\t'; \
} while(0)

// 最后一个字段（无Tab）
#define APPEND_STR_LAST(str) do { \
    if ((str) && (str)[0]) { \
        size_t _l = strlen(str); \
        size_t _c = std::min(_l, buf_size - pos - 1); \
        memcpy(buf+pos, (str), _c); \
        pos += _c; \
    } \
} while(0)

// ─────────────────────────────────────────────────────────
// 输出单个WiFi组（11个字段）
// ─────────────────────────────────────────────────────────
static size_t appendWifi(const ONU_WifiInfo& w,
                          char* buf, size_t buf_size, size_t pos)
{
    APPEND_U64(w.ssid_mac);             // SSIDMAC
    APPEND_U16(w.channel);              // channel
    APPEND_U16(w.ssid_id);              // SSID号
    APPEND_U8 (w.ssid_enabled);         // enabled
    APPEND_STR(w.ssid_standard);        // standard
    APPEND_STR(w.ssid_name);            // name
    APPEND_U8 (w.ssid_advertisement);   // advertisement
    APPEND_STR(w.ssid_encryption_mode); // encryption_mode
    APPEND_I16(w.noise_level);          // noiselevel（有符号）
    APPEND_U16(w.interf_percent);       // interfpercent
    APPEND_U16(w.transmit_power);       // transmitpower
    return pos;
}

// ─────────────────────────────────────────────────────────
// 输出单个WAN流量组（8个字段）
// ─────────────────────────────────────────────────────────
static size_t appendWan(const ONU_WanTraffic& w,
                         char* buf, size_t buf_size, size_t pos)
{
    APPEND_U16(w.index);                // index
    APPEND_STR(w.name);                 // name
    APPEND_DBL(w.avg_rx_rate);          // avg_rx_rate
    APPEND_DBL(w.avg_tx_rate);          // avg_tx_rate
    APPEND_U64(w.down_stats);           // down_stats
    APPEND_DBL(w.max_rx_rate);          // max_rx_rate
    APPEND_DBL(w.max_tx_rate);          // max_tx_rate
    APPEND_U64(w.up_stats);             // up_stats
    return pos;
}

// ─────────────────────────────────────────────────────────
// 输出有效子设备（15个字段，最后一个字段不加Tab）
// ─────────────────────────────────────────────────────────
static size_t appendSubDevice(const ONU_SubDevice& d,
                               char* buf, size_t buf_size,
                               size_t pos, bool is_last)
{
    APPEND_STR(d.name);                 // 1 sub_device_name
    APPEND_STR(d.type);                 // 2 sub_device_type
    APPEND_U64(d.mac);                  // 3 sub_device_mac（uint64）
    APPEND_STR(d.wlan_radio_type);      // 4 wlan_radio_type
    APPEND_I32(d.wlan_radio_power);     // 5 wlan_radio_power（有符号）
    APPEND_U32(d.ip);                   // 6 sub_device_ip
    APPEND_STR(d.lan_port);             // 7 lan_port
    APPEND_DBL(d.avg_rx_rate);          // 8
    APPEND_DBL(d.avg_tx_rate);          // 9
    APPEND_U64(d.down_stats);           // 10
    APPEND_DBL(d.max_rx_rate);          // 11
    APPEND_DBL(d.max_tx_rate);          // 12
    APPEND_U64(d.up_stats);             // 13
    APPEND_U32(d.speed);                // 14 speed（无文档）

    // 15 duplex（最后一个字段，行末无Tab）
    if (is_last) {
        APPEND_STR_LAST(d.duplex);
    } else {
        APPEND_STR(d.duplex);
    }
    return pos;
}

// ─────────────────────────────────────────────────────────
// 输出 NONE 占位子设备（15个字段）
// 模式：NONE\tNONE\tNONE\t0\tNONE\t0\t0\tNONE\t0\t0\t0\t0\t0\t0\tNONE
// ─────────────────────────────────────────────────────────
static const char NONE_SUBDEV_TAB[] =
    "NONE\tNONE\tNONE\t0\tNONE\t0\t0\tNONE\t0\t0\t0\t0\t0\t0\tNONE";
// 末尾不含'\n'，有Tab时在后面加Tab，无Tab时（最后一个）直接用

static size_t appendNoneDevice(char* buf, size_t buf_size,
                                size_t pos, bool is_last)
{
    static constexpr size_t NONE_LEN =
        sizeof(NONE_SUBDEV_TAB) - 1; // 不含'\0'

    NEED(NONE_LEN + 2);
    memcpy(buf + pos, NONE_SUBDEV_TAB, NONE_LEN);
    pos += NONE_LEN;

    if (!is_last) {
        buf[pos++] = '\t';
    }
    return pos;
}

// ─────────────────────────────────────────────────────────
// 序列化主函数
// ─────────────────────────────────────────────────────────
size_t OnuDcsSerializer::serialize(const OnuRecord& r,
                                    char*  buf,
                                    size_t buf_size)
{
    if (!buf || buf_size < 2) return 0;
    size_t pos = 0;

    // ── 1~3 时间 ──────────────────────────────────────────
    APPEND_U32(r.hour_round_time);          //  1
    APPEND_U32(r.min_round_time);           //  2
    APPEND_U32(r.start_time);               //  3

    // ── 4~6 用户/设备标识 ─────────────────────────────────
    APPEND_STR(r.user_account);             //  4
    APPEND_U64(r.user_mac_addr);            //  5
    APPEND_STR(r.device_id);               //  6

    // ── 7~10 事件信息 ─────────────────────────────────────
    APPEND_U16(r.event_code);              //  7
    APPEND_U16(r.sub_event);               //  8
    APPEND_STR(r.warning_reason);          //  9 （非告警时为空）
    APPEND_U16(r.warning_cpu_rate);        // 10

    // ── 11~19 硬件基础信息 ────────────────────────────────
    APPEND_STR(r.cpu_type);                // 11
    APPEND_STR(r.firmware_version);        // 12
    APPEND_U16(r.flash_size);              // 13
    APPEND_STR(r.hardware_version);        // 14
    APPEND_U64(r.onu_mac);                 // 15
    APPEND_STR(r.manufacturer);            // 16
    APPEND_STR(r.model);                   // 17
    APPEND_STR(r.nfc_support);             // 18
    APPEND_U16(r.ram_size);                // 19

    // ── WiFi 0~3（每组11个输出字段，共44字段）────────────
    for (uint8_t i = 0; i < ONU_MAX_WIFI; ++i) {
        pos = appendWifi(r.wifi[i], buf, buf_size, pos);
    }

    // ── 52~71 运行状态（20字段）──────────────────────────
    APPEND_STR(r.boot_time);               // 52
    APPEND_U16(r.cpu);                     // 53
    APPEND_STR(r.lan1_connect_status);     // 54
    APPEND_STR(r.lan2_connect_status);     // 55
    APPEND_STR(r.lan3_connect_status);     // 56
    APPEND_STR(r.lan4_connect_status);     // 57
    APPEND_U32(r.lan_ip);                  // 58
    APPEND_STR(r.pppoe_error);             // 59
    APPEND_STR(r.pppoe_status);            // 60
    APPEND_U32(r.pppoe_up_time);           // 61
    APPEND_U16(r.ram);                     // 62
    APPEND_U32(r.running_time);            // 63
    APPEND_STR(r.sample_time);             // 64
    APPEND_STR(r.user_name);              // 65
    APPEND_STR(r.wan_connect_status);      // 66
    APPEND_U32(r.wan_ip);                  // 67
    APPEND_STR(r.wan_ipv6);               // 68
    APPEND_STR(r.wifi_status);             // 69
    APPEND_DBL(r.pon_rx_power);            // 70
    APPEND_DBL(r.pon_tx_power);            // 71

    // ── WAN 口流量（4组，每组8字段，共32字段）────────────
    for (uint8_t i = 0; i < ONU_MAX_WAN; ++i) {
        pos = appendWan(r.wan[i], buf, buf_size, pos);
    }

    // ── 子设备（固定16条，不足补NONE占位）────────────────
    // 字段104：sub_device_number
    APPEND_U16(r.sub_device_number);

    // 字段105~117：每个子设备15个字段，共16条
    for (uint8_t i = 0; i < ONU_MAX_SUBDEV; ++i) {
        bool is_last = (i == ONU_MAX_SUBDEV - 1);
        const ONU_SubDevice& d = r.sub_devices[i];

        if (d.valid) {
            pos = appendSubDevice(d, buf, buf_size, pos, is_last);
        } else {
            pos = appendNoneDevice(buf, buf_size, pos, is_last);
        }
    }

    return pos;
}
