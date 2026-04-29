#pragma once
#include "../record/stb_record.h"
#include <string>
#include <cstddef>

// ─────────────────────────────────────────────────────────
// StbDcsSerializer
//
// 将 StbRecord 序列化为 Tab 分隔的单行文本
// 字段顺序（5个）：
//   msg_time  user_account  user_mac_address  server_ip  msg_content
//
// 注意：msg_content 是原始 JSON，不做任何转义
//       由于 JSON 中无 \t，不会破坏 Tab 分隔格式
// ─────────────────────────────────────────────────────────
class StbDcsSerializer
{
public:
	// 返回序列化后的完整行（含末尾换行符）
	static std::string serialize(const StbRecord &rec);
};