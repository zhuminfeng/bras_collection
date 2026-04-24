#pragma once
#include <cstdint>
#include <cstring>

static constexpr uint8_t ONU_MAX_WIFI   = 4;
static constexpr uint8_t ONU_MAX_WAN    = 4;
static constexpr uint8_t ONU_MAX_SUBDEV = 16;

// ─────────────────────────────────────────────────────────
// WiFi 接口信息（每组11个输出字段，含3个未编号字段）
// ─────────────────────────────────────────────────────────
struct ONU_WifiInfo {
    uint64_t  ssid_mac              = 0;      // SSID MAC（uint64十进制）
    uint16_t  channel               = 0;      // 信道号（0=关闭）
    uint16_t  ssid_id               = 0;      // SSID编号
    uint8_t   ssid_enabled          = 0;      // 0/1
    char      ssid_standard[8]      = {};     // "11bgn","11ac"
    char      ssid_name[24]         = {};
    uint8_t   ssid_advertisement    = 0;      // 0/1
    char      ssid_encryption_mode[8] = {};   // "MIXED-WPAPSK2"
    int16_t   noise_level           = 0;      // dBm（有符号，如-90）
    uint16_t  interf_percent        = 0;      // 干扰占空比%
    uint16_t  transmit_power        = 0;      // 发射功率%
};

// ─────────────────────────────────────────────────────────
// WAN 口流量统计（8个输出字段）
// ─────────────────────────────────────────────────────────
struct ONU_WanTraffic {
    uint16_t  index                 = 0;
    char      name[32]              = {};
    double    avg_rx_rate           = 0.0;    // 平均接收速率
    double    avg_tx_rate           = 0.0;
    uint64_t  down_stats            = 0;      // 下行流量（字节）
    double    max_rx_rate           = 0.0;
    double    max_tx_rate           = 0.0;
    uint64_t  up_stats              = 0;      // 上行流量（字节）
};

// ─────────────────────────────────────────────────────────
// 子设备信息（15个输出字段，含2个未编号字段speed/duplex）
// valid=false 时序列化输出 NONE 占位行
// ─────────────────────────────────────────────────────────
struct ONU_SubDevice {
    bool      valid                 = false;
    char      name[48]              = {};
    char      type[32]              = {};
    uint64_t  mac                   = 0;      // MAC（uint64十进制）
    char      wlan_radio_type[8]    = {};     // "2.4G","5G",""
    int32_t   wlan_radio_power      = 0;      // dBm（有符号）
    uint32_t  ip                    = 0;      // 子设备IP（主机序）
    char      lan_port[8]           = {};     // "LAN1","SSID5"
    double    avg_rx_rate           = 0.0;
    double    avg_tx_rate           = 0.0;
    uint64_t  down_stats            = 0;
    double    max_rx_rate           = 0.0;
    double    max_tx_rate           = 0.0;
    uint64_t  up_stats              = 0;
    uint32_t  speed                 = 0;      // 100/1000/0(WiFi)
    char      duplex[8]             = {};     // "Full","None","NONE"
};

// ─────────────────────────────────────────────────────────
// ONU 软探针完整记录（对应 raw/onu_YYYYMMDDTHHMMSS.dcs）
// 总输出字段：19 + 4*11 + 20 + 4*8 + 1 + 16*15 = 356
// ─────────────────────────────────────────────────────────
struct OnuRecord {

    // ── 1~3 时间 ──────────────────────────────────────────
    uint32_t  hour_round_time       = 0;    // 整点小时时间戳(秒)
    uint32_t  min_round_time        = 0;    // 整分时间戳(秒)
    uint32_t  start_time            = 0;    // 采集时间(秒)

    // ── 4~6 用户/设备标识 ─────────────────────────────────
    char      user_account[256]     = {};   // 用户账号
    uint64_t  user_mac_addr         = 0;    // 用户设备MAC
    char      device_id[16]         = {};   // ONU序列号(如FHTT716F4E90)

    // ── 7~10 事件信息 ─────────────────────────────────────
    uint16_t  event_code            = 0;    // 1=Boot 2=周期 3=告警
    uint16_t  sub_event             = 0;
    char      warning_reason[32]    = {};   // 告警时非空
    uint16_t  warning_cpu_rate      = 0;    // 告警时CPU利用率

    // ── 11~19 硬件基础信息 ────────────────────────────────
    char      cpu_type[64]          = {};   // "ZX279127S"
    char      firmware_version[16]  = {};   // "V2.0.0"
    uint16_t  flash_size            = 0;    // MB
    char      hardware_version[16]  = {};   // "V2.0"
    uint64_t  onu_mac               = 0;    // ONU MAC
    char      manufacturer[24]      = {};   // "SKYW","ZTE","FiberHome"
    char      model[64]             = {};   // "SK-D742L","F663N"
    char      nfc_support[8]        = {};   // "YES"/"NO"
    uint16_t  ram_size              = 0;    // MB

    // ── WiFi 0~3（每组11个输出字段，含noise/interf/power）─
    ONU_WifiInfo wifi[ONU_MAX_WIFI];

    // ── 52~71 运行状态 ────────────────────────────────────
    char      boot_time[24]         = {};   // "2025-10-26 14:23:40"
    uint16_t  cpu                   = 0;    // CPU利用率%
    char      lan1_connect_status[16] = {}; // "CONNECTED"/"DISCONNECTED"
    char      lan2_connect_status[16] = {};
    char      lan3_connect_status[16] = {};
    char      lan4_connect_status[16] = {};
    uint32_t  lan_ip                = 0;    // LAN口IP（主机序，十进制输出）
    char      pppoe_error[16]       = {};   // "ERROR_NONE"
    char      pppoe_status[16]      = {};   // "CONNECTED"
    uint32_t  pppoe_up_time         = 0;    // 秒
    uint16_t  ram                   = 0;    // 内存利用率%
    uint32_t  running_time          = 0;    // 运行时长(秒)
    char      sample_time[24]       = {};   // "2025-10-28 12:08:08"
    char      user_name[32]         = {};   // 用户名称(一般为空)
    char      wan_connect_status[16]= {};   // "1"/"0"
    uint32_t  wan_ip                = 0;    // WAN口IP（主机序）
    char      wan_ipv6[64]          = {};   // IPv6地址(逗号分隔多个)
    char      wifi_status[16]       = {};   // "CONNECTED"/"DISCONNECTED"
    double    pon_rx_power          = 0.0;  // 接收光功率 dBm
    double    pon_tx_power          = 0.0;  // 发射光功率 dBm

    // ── WAN 口流量（4个，每组8个输出字段）────────────────
    ONU_WanTraffic wan[ONU_MAX_WAN];

    // ── 子设备（最多16个，不足补NONE占位）────────────────
    uint16_t  sub_device_number     = 0;
    ONU_SubDevice sub_devices[ONU_MAX_SUBDEV];

    OnuRecord() { memset(this, 0, sizeof(*this)); }
};
