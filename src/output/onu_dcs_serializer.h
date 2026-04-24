#pragma once

#include "../record/onu_record.h"
#include <cstddef>

// ─────────────────────────────────────────────────────────
// OnuDcsSerializer
//
// 将 OnuRecord 序列化为 Tab 分隔的 DCS 行
// 总字段数：356
//   19(基础) + 4*11(WiFi) + 20(状态) + 4*8(WAN) + 1+16*15(子设备)
//
// 子设备：always输出16条，不足补NONE占位模式
// NONE占位：NONE\tNONE\tNONE\t0\tNONE\t0\t0\tNONE\t0\t0\t0\t0\t0\t0\tNONE
// buf_size 建议 >= 16384
// ─────────────────────────────────────────────────────────
class OnuDcsSerializer {
public:
    static size_t serialize(const OnuRecord& r,
                            char*  buf,
                            size_t buf_size);
};
