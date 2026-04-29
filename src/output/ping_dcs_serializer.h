#pragma once
#include "../record/ping_record.h"
#include <cstddef>

// ─────────────────────────────────────────────────────────
// PingDcsSerializer
//
// 将 PingRecord 序列化为 Tab 分隔的单行文本
// 字段顺序（15个）：
//   hour_round_time  min_round_time  start_time  end_time
//   user_mac_addr    bras_mac_addr   user_account
//   user_ip  server_ip  host_hash  host_name
//   request_count  response_count  total_duration  payload_size
// ─────────────────────────────────────────────────────────
class PingDcsSerializer {
public:
    // buf：调用方提供的缓冲区，sz：缓冲区大小
    // 返回写入的字节数（不含终止\0），0表示失败
    static size_t serialize(const PingRecord& rec,
                            char*             buf,
                            size_t            sz);
};
