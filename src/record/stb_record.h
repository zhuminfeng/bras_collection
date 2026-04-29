#pragma once
#include <cstdint>
#include <cstring>
#include <string>

// ─────────────────────────────────────────────────────────
// 移动机顶盒（CMCC STB）软探针记录
// 文件名前缀：cmcc_stb_
// 对应格式：5个字段，Tab分隔
//
// 字段：
//   1  msg_time          uint32  秒级时间戳
//   2  user_account      string  用户账号（来自Radius）
//   3  user_mac_address  uint64  用户MAC（来自以太层）
//   4  server_ip         uint32  服务器IP（来自IP层目的地址）
//   5  msg_content       string  HTTP Body（原始JSON，最大64KB）
// ─────────────────────────────────────────────────────────
struct StbRecord
{
	uint32_t msg_time = 0;
	char user_account[256] = {};
	uint64_t user_mac_address = 0;
	uint32_t server_ip = 0;

	// JSON body 使用 std::string，不截断原始内容
	// LockFreeQueue 要求 nothrow_move_assignable，std::string满足
	std::string msg_content;

	StbRecord()
	{
		memset(user_account, 0, sizeof(user_account));
	}
};