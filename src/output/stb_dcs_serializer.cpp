#include "stb_dcs_serializer.h"
#include <cstdio>
#include <cstring>

std::string StbDcsSerializer::serialize(const StbRecord &r)
{
	// 前4个字段固定格式：约 300 字节
	char header[512];
	int n = snprintf(header, sizeof(header),
					 "%u\t%s\t%lu\t%u\t",
					 r.msg_time,
					 r.user_account[0] ? r.user_account : "",
					 (unsigned long)r.user_mac_address,
					 r.server_ip);

	if (n <= 0 || (size_t)n >= sizeof(header))
		return {};

	std::string line(header, (size_t)n);
	line.append(r.msg_content); // 追加完整 JSON（不截断）
	return line;
}