#pragma once

#include "../record/onu_record.h"
#include <cstdint>

// ─────────────────────────────────────────────────────────
// ONU 软探针协议解析器
//
// ONU 上报格式：HTTP POST 发送 JSON 或私有 TLV 报文
// 实际部署中常见两种上报方式：
//   1. ONU 直接向采集服务器发 HTTP POST（JSON body）
//   2. ONU 向 BRAS 发 UDP 私有协议，BRAS 转发给采集机
//
// 本解析器处理从 Worker 环收到的 TCP/UDP 载荷：
//   - Content-Type: application/json → parseJson()
//   - 私有 TLV 二进制 → parseTlv()（扩展预留）
//
// 使用方式：
//   OnuParser parser;
//   OnuRecord rec;
//   if (parser.parseJson(payload, len, ts_us, rec)) {
//       file_manager->writeOnu(rec);
//   }
// ─────────────────────────────────────────────────────────
class OnuParser {
public:
    // 解析 JSON 格式的 ONU 软探针上报
    // payload：HTTP body 起始地址（已跳过HTTP头）
    // len：body长度
    // ts_us：包到达时间（微秒）
    // 返回 true 表示解析成功
    bool parseJson(const uint8_t* payload, uint32_t len,
                   uint64_t ts_us, OnuRecord& out);

    // 预留：解析私有TLV格式
    bool parseTlv(const uint8_t* payload, uint32_t len,
                  uint64_t ts_us, OnuRecord& out);

private:
    // ── JSON 解析辅助 ─────────────────────────────────────

    // 从 JSON 字符串中提取字段值（不依赖第三方库，轻量实现）
    // 返回字段值字符串（指向 json_buf 内部），失败返回 nullptr
    static const char* jsonGetStr(const char* json, uint32_t json_len,
                                   const char* key,
                                   char* val_buf, size_t val_buf_size);

    // 提取整数字段（支持浮点→截断为整数）
    static bool jsonGetUint(const char* json, uint32_t json_len,
                             const char* key, uint64_t& out);

    // 提取浮点字段
    static bool jsonGetDouble(const char* json, uint32_t json_len,
                               const char* key, double& out);

    // 提取子对象（返回 { ... } 的起始偏移和长度）
    static const char* jsonGetObject(const char* json, uint32_t json_len,
                                      const char* key,
                                      uint32_t& obj_len);

    // 提取数组中第n个元素（返回元素起始偏移和长度）
    static const char* jsonGetArrayElem(const char* array,
                                         uint32_t array_len,
                                         uint32_t index,
                                         uint32_t& elem_len);

    // 解析 WiFi 信息（从 wifi_list 数组元素）
    static void parseWifiInfo(const char* obj, uint32_t obj_len,
                               ONU_WifiInfo& wifi);

    // 解析 WAN 流量（从 wan_traffic 数组元素）
    static void parseWanTraffic(const char* obj, uint32_t obj_len,
                                 ONU_WanTraffic& wan);

    // 解析子设备（从 sub_device 数组元素）
    static void parseSubDevice(const char* obj, uint32_t obj_len,
                                ONU_SubDevice& dev);

    // MAC字符串 → uint64
    static uint64_t macStrToInt(const char* mac_str);

    // IP字符串 → 主机序uint32
    static uint32_t ipStrToInt(const char* ip_str);
};
