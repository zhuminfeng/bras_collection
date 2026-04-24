#pragma once
#include <Packet.h>
#include <DnsLayer.h>
#include <IPv4Layer.h>
#include "../record/record_types.h"

// ─────────────────────────────────────────────
// DNS 解析器（使用PcapPlusPlus，仅解析信令）
// 同时处理查询和响应：
//   - 查询：记录query_name/type，等待响应匹配
//   - 响应：记录status_code、answers、response_duration
// ─────────────────────────────────────────────
class DnsParser
{
public:
	// 解析单个DNS包（查询或响应）
	// is_response: false=查询包，true=响应包
	// Returns: true表示成功填充out
	bool parse(const pcpp::Packet &pkt,
			   uint64_t ts_us,
			   bool is_response,
			   DnsRecord &out);

private:
	// 将DNS答案序列化为逗号分隔字符串
	static void serializeAnswers(pcpp::DnsLayer *dns,
								 char *buf, size_t buf_size);

	// DNS类型编号→字符串（调试用）
	static const char *queryTypeStr(uint16_t type);
};