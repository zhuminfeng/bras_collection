#include "stb_detector.h"
#include <cstring>
#include <cstdlib>
#include <cctype>

// ─────────────────────────────────────────────────────────
// 快速判断是否为STB上报
// ─────────────────────────────────────────────────────────
bool StbDetector::isStbReport(const HttpSession &h)
{
	// 必须是 POST
	if (h.req.method != HttpMethod::POST)
		return false;

	// ① URL 特征
	if (h.req.url[0])
	{
		if (strstr(h.req.url, "/family/") ||
			strstr(h.req.url, "/stb/") ||
			strstr(h.req.url, "/cmcc/"))
			return true;
	}

	// ② User-Agent 特征
	if (h.req.user_agent[0])
	{
		if (strstr(h.req.user_agent, "SoftDetector") ||
			strstr(h.req.user_agent, "softprobe") ||
			strstr(h.req.user_agent, "SoftProbe"))
			return true;
	}

	// ③ body 特征（快速字符串扫描，不完整解析JSON）
	if (h.req.body_len > 0)
	{
		return hasStbJsonFeature(h.req.body, h.req.body_len);
	}

	return false;
}

// ─────────────────────────────────────────────────────────
// JSON特征检测
// ─────────────────────────────────────────────────────────
bool StbDetector::hasStbJsonFeature(const char *body, uint32_t len)
{
	if (!body || len < 16)
		return false;

	// 同时出现 stbRunTime 和 deviceInfo → 高置信度STB上报
	bool has_stb_run = (memmem(body, len, "stbRunTime", 10) != nullptr);
	bool has_dev_info = (memmem(body, len, "deviceInfo", 10) != nullptr);
	if (has_stb_run && has_dev_info)
		return true;

	// tcpConnectInfo + voiceRegInfo 也是特征
	bool has_tcp = (memmem(body, len, "tcpConnectInfo", 14) != nullptr);
	bool has_voice = (memmem(body, len, "voiceRegInfo", 12) != nullptr);
	if (has_tcp && has_voice)
		return true;

	return false;
}

// ─────────────────────────────────────────────────────────
// 从 JSON body 提取 deviceInfo.macaddress（冒号格式MAC）
// ─────────────────────────────────────────────────────────
static const char *findJsonValue(const char *body, uint32_t len,
								 const char *key,
								 uint32_t &val_len)
{
	// 在 body[0..len) 中查找 "key":"value" 或 "key":value
	uint32_t klen = (uint32_t)strlen(key);
	const char *p = body;
	const char *end = body + len;

	while (p < end)
	{
		const char *found = (const char *)memmem(
			p, end - p, key, klen);
		if (!found)
			return nullptr;

		// 跳过 key，找冒号
		const char *after_key = found + klen;
		while (after_key < end && (*after_key == '"' ||
								   *after_key == ':' || *after_key == ' '))
			++after_key;

		if (after_key >= end)
			return nullptr;

		// 找值的结束
		char delim = (*after_key == '"') ? '"' : ',';
		const char *val_start = after_key;
		if (delim == '"')
			++val_start; // 跳过开头引号

		const char *val_end = val_start;
		while (val_end < end && *val_end != delim &&
			   *val_end != '}' && *val_end != ']')
			++val_end;

		val_len = (uint32_t)(val_end - val_start);
		return val_start;
	}
	return nullptr;
}

uint64_t StbDetector::extractMacFromJson(const char *body, uint32_t len)
{
	// 在 deviceInfo 子对象中找 macaddress
	const char *di_start =
		(const char *)memmem(body, len, "deviceInfo", 10);
	if (!di_start)
		return 0;

	// 找到对应的 { ... }
	const char *brace = (const char *)memchr(
		di_start, '{', (size_t)(body + len - di_start));
	if (!brace)
		return 0;

	// 在子对象范围内找 macaddress
	uint32_t sub_len = (uint32_t)(body + len - brace);
	if (sub_len > 2048)
		sub_len = 2048; // 限制搜索范围

	uint32_t val_len = 0;
	const char *mac_str = findJsonValue(brace, sub_len,
										"macaddress", val_len);
	if (!mac_str || val_len < 17)
		return 0;

	// 解析 "xx:xx:xx:xx:xx:xx"
	uint64_t mac = 0;
	int idx = 0;
	for (uint32_t i = 0; i < val_len && idx < 6; ++i)
	{
		char c = mac_str[i];
		uint8_t nibble = 0;
		if (c >= '0' && c <= '9')
			nibble = (uint8_t)(c - '0');
		else if (c >= 'a' && c <= 'f')
			nibble = (uint8_t)(c - 'a' + 10);
		else if (c >= 'A' && c <= 'F')
			nibble = (uint8_t)(c - 'A' + 10);
		else if (c == ':')
			continue;
		else
			break;

		// 两个nibble合成一个字节
		if ((i % 3) == 0)
		{ // high nibble
			mac |= ((uint64_t)nibble << (8 * (5 - idx) + 4));
		}
		else if ((i % 3) == 1)
		{ // low nibble
			mac |= ((uint64_t)nibble << (8 * (5 - idx)));
			++idx;
		}
	}
	return mac;
}

// ─────────────────────────────────────────────────────────
// 构建 StbRecord
// ─────────────────────────────────────────────────────────
bool StbDetector::buildRecord(const HttpSession &h,
							  uint64_t ts_us,
							  uint64_t user_mac,
							  uint32_t server_ip,
							  const char *user_account,
							  StbRecord &out)
{
	if (h.req.body_len == 0)
		return false;

	out.msg_time = (uint32_t)(ts_us / 1000000);

	// user_account：优先来自Radius表（调用方已传入）
	if (user_account && user_account[0])
		strncpy(out.user_account, user_account, 255);
	else
		out.user_account[0] = '\0';

	// user_mac：优先用以太层MAC，其次从JSON提取
	out.user_mac_address = user_mac;
	if (out.user_mac_address == 0)
	{
		out.user_mac_address = extractMacFromJson(
			h.req.body, h.req.body_len);
	}

	out.server_ip = server_ip;

	// msg_content：原始JSON body（完整保留）
	out.msg_content.assign(h.req.body, h.req.body_len);

	return true;
}