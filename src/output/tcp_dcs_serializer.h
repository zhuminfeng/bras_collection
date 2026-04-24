#pragma once

#include "../record/record_types.h"
#include <cstddef>

// ─────────────────────────────────────────────────────────
// TcpDcsSerializer
//
// 将 TcpSessionRecord 序列化为 Tab 分隔的 DCS 行（39字段）
//
// 与 HttpDcsSerializer 的关键区别：
//   - host_name 为空时输出空字符串（不输出NONE）
//     → 两个连续Tab：...host_hash\t\tuser_port...
//   - 无HTTP应用层字段
// ─────────────────────────────────────────────────────────
class TcpDcsSerializer {
public:
    // 序列化到 buf，返回写入字节数（不含'\0'）
    // buf_size 建议 >= 2048
    static size_t serialize(const TcpSessionRecord& r,
                            char*  buf,
                            size_t buf_size);
};
