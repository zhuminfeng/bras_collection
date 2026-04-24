#include "radius_parser.h"
#include "../utils/time_utils.h"

#include <cstdio>
#include <cstring>
#include <cctype>
#include <arpa/inet.h>
#include <spdlog/spdlog.h>

// ─────────────────────────────────────────────────────────
// Radius数据包最小长度（4字节头 + 16字节Authenticator）
// ─────────────────────────────────────────────────────────
static constexpr uint32_t RADIUS_HEADER_LEN = 20;

// ─────────────────────────────────────────────────────────
// 主解析函数
// ─────────────────────────────────────────────────────────
bool RadiusParser::parse(const uint8_t* payload, uint32_t len,
                          uint32_t src_ip, uint32_t dst_ip,
                          uint64_t bras_mac, uint64_t ts_us,
                          RadiusRecord& out)
{
    if (!payload || len < RADIUS_HEADER_LEN) return false;

    // ── Radius 头部（20字节）─────────────────────────────
    uint8_t  code   = payload[0];
    uint8_t  id     = payload[1];
    uint16_t pkt_len= readBe16(payload + 2);

    if (pkt_len < RADIUS_HEADER_LEN || pkt_len > len) return false;

    // ── 填写基础字段 ──────────────────────────────────────
    out.radius_id   = id;
    out.request_code= code;
    out.bras_mac    = bras_mac;
    out.client_ip   = src_ip;

    // 判断方向：请求(1/4)从NAS→Server，响应(2/3/5)从Server→NAS
    bool is_request = (code == 1 || code == 4 || code == 10);
    if (is_request) {
        out.bras_ip          = src_ip;
        out.radius_server_ip = dst_ip;
        out.start_time       = (double)ts_us / 1e6;
    } else {
        out.bras_ip          = dst_ip;
        out.radius_server_ip = src_ip;
        out.end_time         = (double)ts_us / 1e6;
        out.reply_code       = code;
    }

    // 计算时间戳字段（基于start_time）
    if (out.start_time > 0) {
        out.hour_round_time = TimeUtils::hourRoundTime(out.start_time);
        out.min_round_time  = TimeUtils::minRoundTime(out.start_time);
    }

    // ── 遍历AVP ───────────────────────────────────────────
    uint32_t offset = RADIUS_HEADER_LEN;
    while (offset + 2 <= pkt_len) {
        uint8_t attr_type = payload[offset];
        uint8_t attr_len  = payload[offset + 1];

        if (attr_len < 2 || offset + attr_len > pkt_len) break;

        const uint8_t* val     = payload + offset + 2;
        uint8_t        val_len = attr_len - 2;

        if (attr_type == RadiusAttr::VENDOR_SPECIFIC) {
            parseVsa(val, val_len, out);
        } else {
            parseStdAvp(attr_type, val, val_len, out);
        }

        offset += attr_len;
    }

    // ── 解析nas_port_id中的OLT信息 ───────────────────────
    if (out.nas_port_id[0]) {
        parseNasPortId(out.nas_port_id,
                       out.olt_ip, out.pon_board,
                       out.pon_port, out.onu_no,
                       sizeof(out.onu_no));
    }

    // ── calling_station_id → int ──────────────────────────
    if (out.calling_station_id[0]) {
        out.calling_station_id_int =
            macStrToInt(out.calling_station_id);
    }

    return true;
}

// ─────────────────────────────────────────────────────────
// 标准AVP解析
// ─────────────────────────────────────────────────────────
void RadiusParser::parseStdAvp(uint8_t type, const uint8_t* val,
                                 uint8_t val_len, RadiusRecord& out)
{
    if (val_len == 0) return;

    // 辅助宏
    auto copyStr = [](const uint8_t* v, uint8_t vl,
                      char* dst, size_t dst_size) {
        size_t copy = std::min((size_t)vl, dst_size - 1);
        memcpy(dst, v, copy);
        dst[copy] = '\0';
    };
    auto readU32 = [&]() -> uint32_t {
        if (val_len < 4) return 0;
        return readBe32(val);
    };

    switch (type) {
    case RadiusAttr::USER_NAME:
        copyStr(val, val_len, out.user_name, sizeof(out.user_name));
        break;

    case RadiusAttr::NAS_IP_ADDRESS:
        if (val_len >= 4)
            out.nas_ip = netToHost(readBe32(val));
        // NAS-IP通常也是BRAS IP
        if (out.bras_ip == 0 && val_len >= 4)
            out.bras_ip = out.nas_ip;
        break;

    case RadiusAttr::NAS_PORT:
        out.nas_port = readU32();
        break;

    case RadiusAttr::SERVICE_TYPE:
        out.service_type = readU32();
        break;

    case RadiusAttr::FRAMED_PROTOCOL:
        out.framed_protocol = readU32();
        break;

    case RadiusAttr::FRAMED_IP_ADDRESS:
        if (val_len >= 4)
            out.framed_ip = netToHost(readBe32(val));
        break;

    case RadiusAttr::REPLY_MESSAGE:
        copyStr(val, val_len, out.reply_message,
                sizeof(out.reply_message));
        break;

    case RadiusAttr::SESSION_TIMEOUT:
        out.session_timeout = readU32();
        break;

    case RadiusAttr::IDLE_TIMEOUT:
        out.idle_timeout = readU32();
        break;

    case RadiusAttr::CALLED_STATION_ID:
        copyStr(val, val_len, out.called_station_id,
                sizeof(out.called_station_id));
        break;

    case RadiusAttr::CALLING_STATION_ID:
        copyStr(val, val_len, out.calling_station_id,
                sizeof(out.calling_station_id));
        break;

    case RadiusAttr::NAS_IDENTIFIER:
        copyStr(val, val_len, out.nas_identifier,
                sizeof(out.nas_identifier));
        break;

    case RadiusAttr::ACCT_STATUS_TYPE:
        out.acct_status_type = readU32();
        break;

    case RadiusAttr::ACCT_DELAY_TIME:
        out.acct_delay_time = readU32();
        break;

    case RadiusAttr::ACCT_INPUT_OCTETS:
        out.acct_input_octets = readU32();
        break;

    case RadiusAttr::ACCT_OUTPUT_OCTETS:
        out.acct_output_octets = readU32();
        break;

    case RadiusAttr::ACCT_SESSION_ID:
        copyStr(val, val_len, out.acct_session_id,
                sizeof(out.acct_session_id));
        break;

    case RadiusAttr::ACCT_AUTHENTIC:
        out.acct_authen = readU32();
        break;

    case RadiusAttr::ACCT_SESSION_TIME:
        out.acct_session_time = readU32();
        break;

    case RadiusAttr::ACCT_INPUT_PACKETS:
        out.acct_input_packets = readU32();
        break;

    case RadiusAttr::ACCT_OUTPUT_PACKETS:
        out.acct_output_packets = readU32();
        break;

    case RadiusAttr::ACCT_TERMINATE_CAUSE:
        out.acct_terminate_cause = readU32();
        break;

    case RadiusAttr::ACCT_INPUT_GIGAWORDS:
        out.acct_input_gigawords = readU32();
        break;

    case RadiusAttr::ACCT_OUTPUT_GIGAWORDS:
        out.acct_output_gigawords = readU32();
        break;

    case RadiusAttr::NAS_PORT_TYPE:
        out.nas_port_type = readU32();
        break;

    case RadiusAttr::CONNECT_INFO:
        copyStr(val, val_len, out.connect_info,
                sizeof(out.connect_info));
        break;

    case RadiusAttr::NAS_PORT_ID:
        copyStr(val, val_len, out.nas_port_id,
                sizeof(out.nas_port_id));
        break;

    // ── IPv6 ──────────────────────────────────────────────
    case RadiusAttr::FRAMED_IPV6_PREFIX:
        // prefix格式：reserved(1) + prefix_len(1) + prefix(最长16字节)
        if (val_len >= 4) {
            out.ipv6_prefix_length = val[1];
            // 取前8字节作为高64位
            uint64_t h = 0;
            uint8_t  copy_bytes = std::min((uint8_t)(val_len - 2),
                                           (uint8_t)8);
            for (uint8_t i = 0; i < copy_bytes; ++i)
                h = (h << 8) | val[2 + i];
            out.framed_ipv6_prefix = h;
        }
        break;

    case RadiusAttr::FRAMED_INTERFACE_ID:
        if (val_len >= 8) {
            uint64_t v = 0;
            for (int i = 0; i < 8; ++i)
                v = (v << 8) | val[i];
            out.framed_interface_id = v;
        }
        break;

    case RadiusAttr::DELEGATED_IPV6_PREFIX:
        if (val_len >= 4) {
            out.delegated_ipv6_prefix_length = val[1];
            uint64_t h = 0;
            uint8_t  copy_bytes = std::min((uint8_t)(val_len - 2),
                                           (uint8_t)8);
            for (uint8_t i = 0; i < copy_bytes; ++i)
                h = (h << 8) | val[2 + i];
            out.delegated_ipv6_prefix = h;
        }
        break;

    case RadiusAttr::ACCT_IPV6_INPUT_OCTETS:
        out.acct_ipv6_input_octets = readU32();
        break;

    case RadiusAttr::ACCT_IPV6_OUTPUT_OCTETS:
        out.acct_ipv6_output_octets = readU32();
        break;

    case RadiusAttr::ACCT_IPV6_INPUT_GIGAWORDS:
        out.acct_ipv6_input_gigawords = readU32();
        break;

    case RadiusAttr::ACCT_IPV6_OUTPUT_GIGAWORDS:
        out.acct_ipv6_output_gigawords = readU32();
        break;

    default:
        break;
    }
}

// ─────────────────────────────────────────────────────────
// VSA解析（type=26）
// 结构：Vendor-ID(4) + Sub-Type(1) + Sub-Len(1) + Sub-Val
// 一个VSA AVP可包含多个子属性（取决于厂商实现）
// ─────────────────────────────────────────────────────────
void RadiusParser::parseVsa(const uint8_t* data, uint8_t len,
                              RadiusRecord& out)
{
    if (len < 6) return;  // 至少Vendor-ID(4) + Sub-Type(1) + Sub-Len(1)

    uint32_t vendor_id = readBe32(data);
    uint8_t  offset    = 4;

    while (offset + 2 <= len) {
        uint8_t sub_type = data[offset];
        uint8_t sub_len  = data[offset + 1];

        if (sub_len < 2 || offset + sub_len > len) break;

        const uint8_t* sub_val = data + offset + 2;
        uint8_t sub_val_len    = sub_len - 2;

        if (vendor_id == HuaweiVsa::VENDOR_ID) {
            parseHuaweiVsa(sub_type, sub_val, sub_val_len, out);
        }
        // 可在此扩展其他厂商（ZTE=6972, Cisco=9, etc.）

        offset += sub_len;
    }
}

// ─────────────────────────────────────────────────────────
// Huawei VSA解析（Vendor-ID = 2011）
// ─────────────────────────────────────────────────────────
void RadiusParser::parseHuaweiVsa(uint8_t sub_type,
                                    const uint8_t* val,
                                    uint8_t val_len,
                                    RadiusRecord& out)
{
    switch (sub_type) {
    // ── NAT公网IP + 端口范围 ──────────────────────────────
    // 格式：IP(4) + start_port(2) + end_port(2) 或 IP(4) + port(2)
    case HuaweiVsa::NAT_IP_PORT:
        if (val_len >= 4) {
            out.nat_public_ip = ntohl(readBe32(val));
            if (val_len >= 8) {
                out.nat_start_port = readBe16(val + 4);
                out.nat_end_port   = readBe16(val + 6);
            } else if (val_len >= 6) {
                out.nat_start_port = readBe16(val + 4);
            }
        }
        break;

    // ── 上行带宽（Kbps）──────────────────────────────────
    case HuaweiVsa::INPUT_AVERAGE_RATE:
        if (val_len >= 4)
            out.ul_band_limits = readBe32(val);
        break;

    // ── 下行带宽（Kbps）──────────────────────────────────
    case HuaweiVsa::OUTPUT_AVERAGE_RATE:
        if (val_len >= 4)
            out.dl_band_limits = readBe32(val);
        break;

    default:
        break;
    }
}

// ─────────────────────────────────────────────────────────
// nas_port_id 解析
//
// 支持格式：
//   "trunk {trunk_id} {olt_ip}/{frame}/{slot}/{board}/{sub}/{port}/{onu} {suffix}"
//
// olt_ip   = IP字符串转整数
// pon_board = (frame << 8) | board
// pon_port  = port（路径第5个/分隔字段）
// onu_no    = 16位纯HEX→前4字节ASCII+��8位HEX，否则为空
// ─────────────────────────────────────────────────────────
void RadiusParser::parseNasPortId(const char*  nas_port_id,
                                   uint32_t&    olt_ip,
                                   uint16_t&    pon_board,
                                   uint16_t&    pon_port,
                                   char*        onu_no,
                                   size_t       onu_no_size)
{
    olt_ip    = 0;
    pon_board = 0;
    pon_port  = 0;
    if (onu_no_size > 0) onu_no[0] = '\0';

    if (!nas_port_id || !nas_port_id[0]) return;

    // 在字符串中查找IPv4地址（格式 d.d.d.d）
    const char* p = nas_port_id;
    const char* ip_start = nullptr;

    // 向前扫描，找到"空格 + 数字.数字.数字.数字"的模式
    while (*p) {
        if ((*p == ' ' || p == nas_port_id) && isdigit(*(p+1 > nas_port_id ? p+1 : p))) {
            const char* candidate = (*p == ' ') ? p + 1 : p;
            // 简单验证：包含至少两个点
            int dots = 0;
            const char* q = candidate;
            while (*q && *q != ' ' && *q != '/') {
                if (*q == '.') ++dots;
                ++q;
            }
            if (dots == 3 && *q == '/') {
                ip_start = candidate;
                break;
            }
        }
        ++p;
    }

    if (!ip_start) return;

    // 提取IP字符串
    char ip_buf[32] = {};
    const char* slash = strchr(ip_start, '/');
    if (!slash) return;
    size_t ip_len = std::min((size_t)(slash - ip_start),
                              sizeof(ip_buf) - 1);
    memcpy(ip_buf, ip_start, ip_len);
    ip_buf[ip_len] = '\0';

    struct in_addr addr{};
    if (inet_pton(AF_INET, ip_buf, &addr) != 1) return;
    olt_ip = ntohl(addr.s_addr);

    // 解析 /frame/slot/board/sub/port/onu 部分
    // 最多6个 / 分隔段
    const char* parts[6] = {};
    int         part_cnt = 0;
    const char* cur      = slash + 1;

    for (int i = 0; i < 6 && *cur; ++i) {
        parts[part_cnt++] = cur;
        const char* next = strchr(cur, '/');
        if (!next) break;
        cur = next + 1;
    }

    // part_cnt >= 5 时才能提取完整字段
    // 格式：frame(0) / slot(1) / board(2) / sub(3) / port(4) / onu(5)
    if (part_cnt >= 5) {
        uint32_t frame = (uint32_t)atoi(parts[0]);
        uint32_t board = (uint32_t)atoi(parts[2]);
        uint32_t port  = (uint32_t)atoi(parts[4]);

        pon_board = (uint16_t)((frame << 8) | (board & 0xFF));
        pon_port  = (uint16_t)(port & 0xFFFF);
    }

    if (part_cnt >= 6 && onu_no_size > 0) {
        // 提取onu_id（去掉尾部空格和后缀）
        char onu_raw[64] = {};
        const char* onu_start = parts[5];
        const char* onu_end   = onu_start;
        while (*onu_end && *onu_end != ' ' && *onu_end != '\t')
            ++onu_end;
        size_t onu_len = std::min((size_t)(onu_end - onu_start),
                                   sizeof(onu_raw) - 1);
        memcpy(onu_raw, onu_start, onu_len);
        onu_raw[onu_len] = '\0';

        decodeOnuId(onu_raw, onu_no, onu_no_size);
    }
}

// ─────────────────────────────────────────────────────────
// ONT ID解码
//
// 规则：
//   输入为16个纯HEX字符 → 前8字节转ASCII(4字节)+后8字节HEX
//   "464854542ED3E7A0" → "FHTT" + "2ED3E7A0" = "FHTT2ED3E7A0"
//
//   输入为其他格式 → 不解码，onu_no留空
//   "SKYWA8BD00C2"（含非HEX字符Y）→ ""
// ─────────────────────────────────────────────────────────
void RadiusParser::decodeOnuId(const char* raw_onu,
                                char* out, size_t out_size)
{
    out[0] = '\0';
    if (!raw_onu || !raw_onu[0]) return;

    size_t len = strlen(raw_onu);

    // 只处理恰好16个字符的纯HEX字符串
    if (len != 16 || !isAllHex(raw_onu, 16)) return;

    // 前8个HEX字符（4字节）→ ASCII
    char vendor[5] = {};
    for (int i = 0; i < 4; ++i) {
        char hex2[3] = { raw_onu[i*2], raw_onu[i*2+1], 0 };
        unsigned byte = 0;
        sscanf(hex2, "%x", &byte);
        vendor[i] = (char)byte;
    }
    vendor[4] = '\0';

    // 后8个HEX字符直接保留
    // 合并：vendor(4) + serial(8) = 12字符
    snprintf(out, out_size, "%s%s", vendor, raw_onu + 8);
}

bool RadiusParser::isAllHex(const char* s, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        char c = s[i];
        if (!((c>='0'&&c<='9') || (c>='A'&&c<='F') ||
              (c>='a'&&c<='f')))
            return false;
    }
    return true;
}

// ─────────────────────────────────────────────────────────
// MAC字符串 → uint64
// 支持：AA:BB:CC:DD:EE:FF / AA-BB-CC-DD-EE-FF / AABBCCDDEEFF
// ─────────────────────────────────────────────────────────
uint64_t RadiusParser::macStrToInt(const char* mac_str) {
    if (!mac_str || !mac_str[0]) return 0;

    uint8_t bytes[6] = {};
    int parsed = sscanf(mac_str,
        "%hhx%*c%hhx%*c%hhx%*c%hhx%*c%hhx%*c%hhx",
        &bytes[0], &bytes[1], &bytes[2],
        &bytes[3], &bytes[4], &bytes[5]);
    if (parsed == 6) {
        return ((uint64_t)bytes[0] << 40) |
               ((uint64_t)bytes[1] << 32) |
               ((uint64_t)bytes[2] << 24) |
               ((uint64_t)bytes[3] << 16) |
               ((uint64_t)bytes[4] <<  8) |
                (uint64_t)bytes[5];
    }

    // 尝试无分隔符格式：AABBCCDDEEFF
    if (strlen(mac_str) == 12 && isAllHex(mac_str, 12)) {
        uint64_t result = 0;
        for (int i = 0; i < 6; ++i) {
            char hex2[3] = { mac_str[i*2], mac_str[i*2+1], 0 };
            unsigned byte = 0;
            sscanf(hex2, "%x", &byte);
            result = (result << 8) | byte;
        }
        return result;
    }

    return 0;
}
