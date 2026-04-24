#include "onu_parser.h"
#include "../utils/time_utils.h"

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <arpa/inet.h>
#include <spdlog/spdlog.h>

// ─────────────────────────────────────────────────────────
// 轻量JSON解析工具（不依赖nlohmann/json，减少运行时开销）
//
// 仅支持 ONU 上报 JSON 的固定格式，不做通用语法树解析
// 策略：字符串搜索 "key": value，按类型读取value
// ─────────────────────────────────────────────────────────

// 跳过空白
static const char* skipWs(const char* p, const char* end) {
    while (p < end && (*p == ' ' || *p == '\t' ||
                       *p == '\r' || *p == '\n'))
        ++p;
    return p;
}

// 在 json[0..json_len) 中查找 "key":\s*
// 返回 value 起始位置，失败返回 nullptr
static const char* findKey(const char* json, uint32_t json_len,
                             const char* key)
{
    // 构造搜索模式 "\"key\":"
    char pattern[256];
    int plen = snprintf(pattern, sizeof(pattern), "\"%s\":", key);
    if (plen <= 0 || (uint32_t)plen >= sizeof(pattern)) return nullptr;

    const char* end  = json + json_len;
    const char* p    = json;

    while (p + plen <= end) {
        const char* found = (const char*)memmem(p, end - p,
                                                 pattern, plen);
        if (!found) return nullptr;

        const char* val_start = found + plen;
        val_start = skipWs(val_start, end);
        return val_start;
    }
    return nullptr;
}

// 读取JSON字符串值（跳过引号，处理转义）
// 返回 true，val 填入去引号的字符串
static bool readJsonString(const char* p, const char* end,
                            char* out, size_t out_size,
                            uint32_t* consumed = nullptr)
{
    if (!p || p >= end || *p != '"') return false;
    ++p; // 跳过开头 "
    size_t i = 0;
    const char* start = p;
    while (p < end && *p != '"') {
        if (*p == '\\') {
            ++p; // 跳过转义字符
            if (p >= end) break;
        }
        if (i + 1 < out_size) out[i++] = *p;
        ++p;
    }
    out[i] = '\0';
    if (consumed) *consumed = (uint32_t)(p + 1 - start + 1);
    return true;
}

// 跳过一个JSON值（用于数组遍历）
static const char* skipJsonValue(const char* p, const char* end) {
    p = skipWs(p, end);
    if (p >= end) return p;

    if (*p == '"') {
        ++p;
        while (p < end && *p != '"') {
            if (*p == '\\') ++p;
            ++p;
        }
        if (p < end) ++p;
    } else if (*p == '{' || *p == '[') {
        char open  = *p;
        char close = (open == '{') ? '}' : ']';
        int  depth = 1;
        ++p;
        while (p < end && depth > 0) {
            if (*p == '"') {
                ++p;
                while (p < end && *p != '"') {
                    if (*p == '\\') ++p;
                    ++p;
                }
                if (p < end) ++p;
            } else {
                if (*p == open)  ++depth;
                if (*p == close) --depth;
                ++p;
            }
        }
    } else {
        while (p < end && *p != ',' && *p != '}' && *p != ']')
            ++p;
    }
    return p;
}

// ─────────────────────────────────────────────────────────
// JSON解���辅助方法
// ─────────────────────────────────────────────────────────
const char* OnuParser::jsonGetStr(const char* json, uint32_t json_len,
                                   const char* key,
                                   char* val_buf, size_t val_buf_size)
{
    const char* end = json + json_len;
    const char* p   = findKey(json, json_len, key);
    if (!p) { val_buf[0] = '\0'; return nullptr; }
    if (!readJsonString(p, end, val_buf, val_buf_size)) {
        val_buf[0] = '\0';
        return nullptr;
    }
    return val_buf;
}

bool OnuParser::jsonGetUint(const char* json, uint32_t json_len,
                              const char* key, uint64_t& out)
{
    const char* end = json + json_len;
    const char* p   = findKey(json, json_len, key);
    if (!p) return false;
    p = skipWs(p, end);
    if (*p == '"') {
        char tmp[32];
        if (!readJsonString(p, end, tmp, sizeof(tmp))) return false;
        out = (uint64_t)strtoull(tmp, nullptr, 10);
    } else {
        out = (uint64_t)strtoull(p, nullptr, 10);
    }
    return true;
}

bool OnuParser::jsonGetDouble(const char* json, uint32_t json_len,
                               const char* key, double& out)
{
    const char* end = json + json_len;
    const char* p   = findKey(json, json_len, key);
    if (!p) return false;
    p = skipWs(p, end);
    if (*p == '"') {
        char tmp[32];
        if (!readJsonString(p, end, tmp, sizeof(tmp))) return false;
        out = strtod(tmp, nullptr);
    } else {
        out = strtod(p, nullptr);
    }
    return true;
}

const char* OnuParser::jsonGetObject(const char* json,
                                      uint32_t json_len,
                                      const char* key,
                                      uint32_t& obj_len)
{
    const char* end = json + json_len;
    const char* p   = findKey(json, json_len, key);
    if (!p) { obj_len = 0; return nullptr; }
    p = skipWs(p, end);
    if (p >= end || (*p != '{' && *p != '[')) {
        obj_len = 0;
        return nullptr;
    }
    char open  = *p;
    char close = (open == '{') ? '}' : ']';
    const char* start = p;
    int depth = 1;
    ++p;
    while (p < end && depth > 0) {
        if (*p == '"') {
            ++p;
            while (p < end && *p != '"') {
                if (*p == '\\') ++p;
                ++p;
            }
            if (p < end) ++p;
        } else {
            if (*p == open)  ++depth;
            if (*p == close) --depth;
            ++p;
        }
    }
    obj_len = (uint32_t)(p - start);
    return start;
}

const char* OnuParser::jsonGetArrayElem(const char* array,
                                         uint32_t array_len,
                                         uint32_t index,
                                         uint32_t& elem_len)
{
    const char* end = array + array_len;
    const char* p   = array;

    // 跳过 [
    if (*p == '[') ++p;

    uint32_t idx = 0;
    while (p < end) {
        p = skipWs(p, end);
        if (p >= end || *p == ']') break;

        const char* elem_start = p;
        p = skipJsonValue(p, end);
        uint32_t elen = (uint32_t)(p - elem_start);

        if (idx == index) {
            elem_len = elen;
            return elem_start;
        }
        ++idx;

        p = skipWs(p, end);
        if (p < end && *p == ',') ++p;
    }
    elem_len = 0;
    return nullptr;
}

// ─────────────────────────────────────────────────────────
// MAC字符串 → uint64（支持 : / - 分隔）
// ─────────────────────────────────────────────────────────
uint64_t OnuParser::macStrToInt(const char* mac_str) {
    if (!mac_str || !mac_str[0]) return 0;
    uint8_t b[6] = {};
    int n = sscanf(mac_str,
        "%hhx%*c%hhx%*c%hhx%*c%hhx%*c%hhx%*c%hhx",
        &b[0],&b[1],&b[2],&b[3],&b[4],&b[5]);
    if (n != 6) return 0;
    return ((uint64_t)b[0]<<40)|((uint64_t)b[1]<<32)|
           ((uint64_t)b[2]<<24)|((uint64_t)b[3]<<16)|
           ((uint64_t)b[4]<< 8)| (uint64_t)b[5];
}

// ─────────────────────────────────────────────────────────
// IP字符串 → 主机序uint32
// ─────────────────────────────────────────────────────────
uint32_t OnuParser::ipStrToInt(const char* ip_str) {
    if (!ip_str || !ip_str[0]) return 0;
    struct in_addr addr{};
    if (inet_pton(AF_INET, ip_str, &addr) != 1) return 0;
    return ntohl(addr.s_addr);
}

// ─────────────────────────────────────────────────────────
// 解析单个WiFi信息对象
// ─────────────────────────────────────────────────────────
void OnuParser::parseWifiInfo(const char* obj, uint32_t obj_len,
                               ONU_WifiInfo& wifi)
{
    char tmp[64];

    // MAC → uint64
    if (jsonGetStr(obj, obj_len, "SSIDMAC", tmp, sizeof(tmp)))
        wifi.ssid_mac = macStrToInt(tmp);

    // channel → uint16（可能是字符串"10"或整数10）
    {
        uint64_t v = 0;
        if (jsonGetUint(obj, obj_len, "channel", v))
            wifi.channel = (uint16_t)v;
    }
    {
        uint64_t v = 0;
        if (jsonGetUint(obj, obj_len, "SSID", v))
            wifi.ssid_id = (uint16_t)v;
        if (jsonGetUint(obj, obj_len, "SSID_enabled", v))
            wifi.ssid_enabled = (uint8_t)v;
        if (jsonGetUint(obj, obj_len, "SSID_advertisement", v))
            wifi.ssid_advertisement = (uint8_t)v;
    }
    jsonGetStr(obj, obj_len, "SSID_standard",
               wifi.ssid_standard, sizeof(wifi.ssid_standard));
    jsonGetStr(obj, obj_len, "SSID_name",
               wifi.ssid_name,     sizeof(wifi.ssid_name));
    jsonGetStr(obj, obj_len, "SSID_encryption_mode",
               wifi.ssid_encryption_mode,
               sizeof(wifi.ssid_encryption_mode));
    {
        double v = 0.0;
        if (jsonGetDouble(obj, obj_len, "_noiselevel", v))
            wifi.noise_level = (int16_t)v;
        if (jsonGetDouble(obj, obj_len, "_interfpercent", v))
            wifi.interf_percent = (uint16_t)v;
        if (jsonGetDouble(obj, obj_len, "_transmitpower", v))
            wifi.transmit_power = (uint16_t)v;
    }
}

// ─────────────────────────────────────────────────────────
// 解析单个WAN流量对象
// ─────────────────────────────────────────────────────────
void OnuParser::parseWanTraffic(const char* obj, uint32_t obj_len,
                                 ONU_WanTraffic& wan)
{
    uint64_t v = 0;
    if (jsonGetUint(obj, obj_len, "traffic_index", v))
        wan.index = (uint16_t)v;
    jsonGetStr(obj, obj_len, "traffic_name",
               wan.name, sizeof(wan.name));
    jsonGetDouble(obj, obj_len, "traffic_avg_rx_rate", wan.avg_rx_rate);
    jsonGetDouble(obj, obj_len, "traffic_avg_tx_rate", wan.avg_tx_rate);
    if (jsonGetUint(obj, obj_len, "traffic_down_stats", v))
        wan.down_stats = v;
    jsonGetDouble(obj, obj_len, "traffic_max_rx_rate", wan.max_rx_rate);
    jsonGetDouble(obj, obj_len, "traffic_max_tx_rate", wan.max_tx_rate);
    if (jsonGetUint(obj, obj_len, "traffic_up_stats", v))
        wan.up_stats = v;
}

// ─────────────────────────────────────────────────────────
// 解析单个子设备对象
// ─────────────────────────────────────────────────────────
void OnuParser::parseSubDevice(const char* obj, uint32_t obj_len,
                                ONU_SubDevice& dev)
{
    char tmp[64];
    uint64_t v = 0;

    dev.valid = true;
    jsonGetStr(obj, obj_len, "sub_device_name",
               dev.name, sizeof(dev.name));
    jsonGetStr(obj, obj_len, "sub_device_type",
               dev.type, sizeof(dev.type));

    if (jsonGetStr(obj, obj_len, "sub_device_mac",
                   tmp, sizeof(tmp)))
        dev.mac = macStrToInt(tmp);

    jsonGetStr(obj, obj_len, "sub_device_wlan_radio_type",
               dev.wlan_radio_type, sizeof(dev.wlan_radio_type));

    {
        double dv = 0.0;
        if (jsonGetDouble(obj, obj_len, "sub_device_wlan_radio_power", dv))
            dev.wlan_radio_power = (int32_t)dv;
    }

    if (jsonGetStr(obj, obj_len, "sub_device_ip", tmp, sizeof(tmp)))
        dev.ip = ipStrToInt(tmp);

    jsonGetStr(obj, obj_len, "sub_device_lan_port",
               dev.lan_port, sizeof(dev.lan_port));

    jsonGetDouble(obj, obj_len, "sub_device_avg_rx_rate", dev.avg_rx_rate);
    jsonGetDouble(obj, obj_len, "sub_device_avg_tx_rate", dev.avg_tx_rate);
    if (jsonGetUint(obj, obj_len, "sub_device_down_stats", v))
        dev.down_stats = v;
    jsonGetDouble(obj, obj_len, "sub_device_max_rx_rate", dev.max_rx_rate);
    jsonGetDouble(obj, obj_len, "sub_device_max_tx_rate", dev.max_tx_rate);
    if (jsonGetUint(obj, obj_len, "sub_device_up_stats", v))
        dev.up_stats = v;
    if (jsonGetUint(obj, obj_len, "sub_device_speed", v))
        dev.speed = (uint32_t)v;
    jsonGetStr(obj, obj_len, "sub_device_duplex",
               dev.duplex, sizeof(dev.duplex));
}

// ─────────────────────────────────────────────────────────
// 主解析函数
// ─────────────────────────────────────────────────────────
bool OnuParser::parseJson(const uint8_t* payload, uint32_t len,
                           uint64_t ts_us, OnuRecord& out)
{
    if (!payload || len < 2) return false;
    const char* json = (const char*)payload;
    uint64_t v = 0;
    char tmp[256];

    // ── 1~3 时间 ──────────────────────────────────────────
    out.start_time      = (uint32_t)(ts_us / 1000000);
    out.hour_round_time = TimeUtils::hourRoundTime((double)out.start_time);
    out.min_round_time  = TimeUtils::minRoundTime((double)out.start_time);

    // ── 4~6 用户/设备标识 ─────────────────────────────────
    jsonGetStr(json, len, "user_account",
               out.user_account, sizeof(out.user_account));

    if (jsonGetStr(json, len, "user_mac_addr", tmp, sizeof(tmp)))
        out.user_mac_addr = macStrToInt(tmp);

    jsonGetStr(json, len, "device_id",
               out.device_id, sizeof(out.device_id));

    // ── 7~10 事件信息 ─────────────────────────────────────
    if (jsonGetUint(json, len, "event_code", v))
        out.event_code = (uint16_t)v;
    if (jsonGetUint(json, len, "sub_event", v))
        out.sub_event = (uint16_t)v;
    jsonGetStr(json, len, "warning_reason",
               out.warning_reason, sizeof(out.warning_reason));
    if (jsonGetUint(json, len, "warning_cpu_rate", v))
        out.warning_cpu_rate = (uint16_t)v;

    // ── 11~19 硬件基础信息 ────────────────────────────────
    jsonGetStr(json, len, "cpu_type",
               out.cpu_type, sizeof(out.cpu_type));
    jsonGetStr(json, len, "firmware_version",
               out.firmware_version, sizeof(out.firmware_version));
    if (jsonGetUint(json, len, "flash_size", v))
        out.flash_size = (uint16_t)v;
    jsonGetStr(json, len, "hardware_version",
               out.hardware_version, sizeof(out.hardware_version));
    if (jsonGetStr(json, len, "onu_mac", tmp, sizeof(tmp)))
        out.onu_mac = macStrToInt(tmp);
    jsonGetStr(json, len, "manufacturer",
               out.manufacturer, sizeof(out.manufacturer));
    jsonGetStr(json, len, "model",
               out.model, sizeof(out.model));
    jsonGetStr(json, len, "nfc_support",
               out.nfc_support, sizeof(out.nfc_support));
    if (jsonGetUint(json, len, "ram_size", v))
        out.ram_size = (uint16_t)v;

    // ── WiFi 0~3 ──────────────────────────────────────────
    uint32_t arr_len = 0;
    const char* wifi_arr =
        jsonGetObject(json, len, "wifi_list", arr_len);
    if (wifi_arr && arr_len > 0) {
        for (uint8_t i = 0; i < ONU_MAX_WIFI; ++i) {
            uint32_t elem_len = 0;
            const char* elem =
                jsonGetArrayElem(wifi_arr, arr_len, i, elem_len);
            if (elem && elem_len > 0)
                parseWifiInfo(elem, elem_len, out.wifi[i]);
        }
    }

    // ── 52~71 运行状态 ────────────────────────────────────
    jsonGetStr(json, len, "boot_time",
               out.boot_time, sizeof(out.boot_time));
    if (jsonGetUint(json, len, "cpu", v))
        out.cpu = (uint16_t)v;
    jsonGetStr(json, len, "lan1_connect_status",
               out.lan1_connect_status, sizeof(out.lan1_connect_status));
    jsonGetStr(json, len, "lan2_connect_status",
               out.lan2_connect_status, sizeof(out.lan2_connect_status));
    jsonGetStr(json, len, "lan3_connect_status",
               out.lan3_connect_status, sizeof(out.lan3_connect_status));
    jsonGetStr(json, len, "lan4_connect_status",
               out.lan4_connect_status, sizeof(out.lan4_connect_status));

    if (jsonGetStr(json, len, "lan_ip", tmp, sizeof(tmp)))
        out.lan_ip = ipStrToInt(tmp);

    jsonGetStr(json, len, "PPPOE_error",
               out.pppoe_error, sizeof(out.pppoe_error));
    jsonGetStr(json, len, "PPPOE_status",
               out.pppoe_status, sizeof(out.pppoe_status));
    if (jsonGetUint(json, len, "PPPOE_up_time", v))
        out.pppoe_up_time = (uint32_t)v;
    if (jsonGetUint(json, len, "ram", v))
        out.ram = (uint16_t)v;
    if (jsonGetUint(json, len, "running_time", v))
        out.running_time = (uint32_t)v;
    jsonGetStr(json, len, "sample_time",
               out.sample_time, sizeof(out.sample_time));
    jsonGetStr(json, len, "user_name",
               out.user_name, sizeof(out.user_name));
    jsonGetStr(json, len, "wan_connect_status",
               out.wan_connect_status, sizeof(out.wan_connect_status));

    if (jsonGetStr(json, len, "wan_ip", tmp, sizeof(tmp)))
        out.wan_ip = ipStrToInt(tmp);

    jsonGetStr(json, len, "wan_ipv6",
               out.wan_ipv6, sizeof(out.wan_ipv6));
    jsonGetStr(json, len, "wifi_status",
               out.wifi_status, sizeof(out.wifi_status));
    jsonGetDouble(json, len, "pon_rx_power", out.pon_rx_power);
    jsonGetDouble(json, len, "pon_tx_power", out.pon_tx_power);

    // ── WAN 口流量 0~3 ────────────────────────────────────
    uint32_t wan_arr_len = 0;
    const char* wan_arr =
        jsonGetObject(json, len, "wan_traffic", wan_arr_len);
    if (wan_arr && wan_arr_len > 0) {
        for (uint8_t i = 0; i < ONU_MAX_WAN; ++i) {
            uint32_t elem_len = 0;
            const char* elem =
                jsonGetArrayElem(wan_arr, wan_arr_len, i, elem_len);
            if (elem && elem_len > 0)
                parseWanTraffic(elem, elem_len, out.wan[i]);
        }
    }

    // ── 子设备 ────────────────────────────────────────────
    if (jsonGetUint(json, len, "sub_device_number", v))
        out.sub_device_number = (uint16_t)std::min(v,
            (uint64_t)ONU_MAX_SUBDEV);

    uint32_t sub_arr_len = 0;
    const char* sub_arr =
        jsonGetObject(json, len, "sub_device", sub_arr_len);
    if (sub_arr && sub_arr_len > 0) {
        for (uint8_t i = 0; i < out.sub_device_number; ++i) {
            uint32_t elem_len = 0;
            const char* elem =
                jsonGetArrayElem(sub_arr, sub_arr_len, i, elem_len);
            if (elem && elem_len > 0)
                parseSubDevice(elem, elem_len, out.sub_devices[i]);
        }
    }

    return true;
}

bool OnuParser::parseTlv(const uint8_t* /*payload*/, uint32_t /*len*/,
                          uint64_t /*ts_us*/, OnuRecord& /*out*/)
{
    // 预留：私有TLV格式（当前ONU均使用JSON上报）
    return false;
}
