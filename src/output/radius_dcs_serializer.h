#pragma once

#include "../record/radius_record.h"
#include <cstddef>

// ─────────────────────────────────────────────────────────
// RadiusDcsSerializer
//
// 将 RadiusRecord 序列化为 Tab 分隔的 DCS 行（55个字段）
//
// 空字符串字段：输出空（两个连续Tab），不输出NONE
// 数值字段为0：正常输出 "0"
// ─────────────────────────────────────────────────────────
class RadiusDcsSerializer {
public:
    // buf_size 建议 >= 4096
    static size_t serialize(const RadiusRecord& r,
                            char*  buf,
                            size_t buf_size);
};
