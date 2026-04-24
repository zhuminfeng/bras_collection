#pragma once

#include "../record/record_types.h"
#include <cstdint>
#include <cstring>
#include <arpa/inet.h>

// ─────────────────────────────────────────────────────────
// Radius 标准 AVP 类型编号
// ─────────────────────────────────────────────────────────
namespace RadiusAttr {
    static constexpr uint8_t USER_NAME             =  1;
    static constexpr uint8_t NAS_IP_ADDRESS        =  4;
    static constexpr uint8_t NAS_PORT              =  5;
    static constexpr uint8_t SERVICE_TYPE          =  6;
    static constexpr uint8_t FRAMED_PROTOCOL       =  7;
    static constexpr uint8_t FRAMED_IP_ADDRESS     =  8;
    static constexpr uint8_t REPLY_MESSAGE         = 18;
    static constexpr uint8_t SESSION_TIMEOUT       = 27;
    static constexpr uint8_t IDLE_TIMEOUT          = 28;
    static constexpr uint8_t CALLED_STATION_ID     = 30;
    static constexpr uint8_t CALLING_STATION_ID    = 31;
    static constexpr uint8_t NAS_IDENTIFIER        = 32;
    static constexpr uint8_t ACCT_STATUS_TYPE      = 40;
    static constexpr uint8_t ACCT_DELAY_TIME       = 41;
    static constexpr uint8_t ACCT_INPUT_OCTETS     = 42;
    static constexpr uint8_t ACCT_OUTPUT_OCTETS    = 43;
    static constexpr uint8_t ACCT_SESSION_ID       = 44;
    static constexpr uint8_t ACCT_AUTHENTIC        = 45;
    static constexpr uint8_t ACCT_SESSION_TIME     = 46;
    static constexpr uint8_t ACCT_INPUT_PACKETS    = 47;
    static constexpr uint8_t ACCT_OUTPUT_PACKETS   = 48;
    static constexpr uint8_t ACCT_TERMINATE_CAUSE  = 49;
    static constexpr uint8_t ACCT_INPUT_GIGAWORDS  = 52;
    static constexpr uint8_t ACCT_OUTPUT_GIGAWORDS = 53;
    static constexpr uint8_t NAS_PORT_TYPE         = 61;
    static constexpr uint8_t VENDOR_SPECIFIC       = 26;
    static constexpr uint8_t CONNECT_INFO          = 77;
    static constexpr uint8_t NAS_PORT_ID           = 87;
    // IPv6
    static constexpr uint8_t FRAMED_IPV6_PREFIX    = 97;
    static constexpr uint8_t FRAMED_INTERFACE_ID   = 96;
    static constexpr uint8_t DELEGATED_IPV6_PREFIX = 123;
    // Acct IPv6 (RFC 6572)
    static constexpr uint8_t ACCT_IPV6_INPUT_OCTETS      = 169;
    static constexpr uint8_t ACCT_IPV6_OUTPUT_OCTETS     = 170;
    static constexpr uint8_t ACCT_IPV6_INPUT_GIGAWORDS   = 171;
    static constexpr uint8_t ACCT_IPV6_OUTPUT_GIGAWORDS  = 172;
}

// ─────────────────────────────────────────────────────────
// Huawei VSA 子类型（Vendor-ID = 2011）
// ─────────────────────────────────────────────────────────
namespace HuaweiVsa {
    static constexpr uint32_t VENDOR_ID             = 2011;
    static constexpr uint8_t  NAT_IP_PORT           = 26;  // NAT公网IP+端口范围
    static constexpr uint8_t  INPUT_AVERAGE_RATE    = 82;  // 上行带宽(Kbps)
    static constexpr uint8_t  OUTPUT_AVERAGE_RATE   = 83;  // 下行带宽(Kbps)
    static constexpr uint8_t  INPUT_PEAK_RATE       = 84;
    static constexpr uint8_t  OUTPUT_PEAK_RATE      = 85;
}

// ─────────────────────────────────────────────────────────
// RadiusParser
//
// 输入：原始Radius UDP payload（不含Ethernet/IP/UDP头）
// 输出：填充RadiusRecord
//
// 使用方式：
//   RadiusParser parser;
//   parser.parse(udp_payload, len, src_ip, dst_ip,
//                bras_mac, ts_us, rec);
// ─────────────────────────────────────────────────────────
class RadiusParser {
public:
    // 解析Radius UDP payload
    // src_ip/dst_ip：UDP层源/目的IP（主机序）
    // bras_mac：以太头提取的MAC
    // ts_us：包到达时间（微秒）
    // 返回 true 表示解析成功
    bool parse(const uint8_t* payload, uint32_t len,
               uint32_t src_ip, uint32_t dst_ip,
               uint64_t bras_mac, uint64_t ts_us,
               RadiusRecord& out);

    // 从nas_port_id字符串解析OLT/PON信息
    // 格式示例：
    //   "trunk 2/0/12:32.582 10.40.1.98/0/0/0/0/1/464854542ED3E7A0 GP"
    static void parseNasPortId(const char*  nas_port_id,
                                uint32_t&    olt_ip,
                                uint16_t&    pon_board,
                                uint16_t&    pon_port,
                                char*        onu_no,
                                size_t       onu_no_size);

    // calling_station_id MAC字符串 → uint64
    // 支持格式：AA:BB:CC:DD:EE:FF / AA-BB-CC-DD-EE-FF
    static uint64_t macStrToInt(const char* mac_str);

private:
    // 解析标准AVP（type 1~172）
    void parseStdAvp(uint8_t type, const uint8_t* val,
                     uint8_t val_len, RadiusRecord& out);

    // 解析VSA（type=26）
    void parseVsa(const uint8_t* vsa_data, uint8_t vsa_len,
                  RadiusRecord& out);

    // 解析Huawei VSA子属性
    void parseHuaweiVsa(uint8_t sub_type,
                        const uint8_t* val, uint8_t val_len,
                        RadiusRecord& out);

    // 读取大端序4字节整数
    static uint32_t readBe32(const uint8_t* p) {
        return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
    }

    // 读取大端序2字节整数
    static uint16_t readBe16(const uint8_t* p) {
        return (uint16_t)((p[0] << 8) | p[1]);
    }

    // uint32_t IP（网络序）→ 主机序
    static uint32_t netToHost(uint32_t net) {
        return ntohl(net);
    }

    // 将纯16字符HEX ONT ID转为可读格式
    // "464854542ED3E7A0" → "FHTT2ED3E7A0"
    static void decodeOnuId(const char* raw_onu,
                             char* out, size_t out_size);

    // 判断字符串是否全为十六进制字符
    static bool isAllHex(const char* s, size_t len);
};
