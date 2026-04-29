#pragma once

#include "../record/stb_record.h"
#include "../session/http_session.h"
#include <cstdint>
#include <cstring>

// ─────────────────────────────────────────────────────────
// StbDetector
//
// 职责：
//   判断一个 HTTP 流是否是 CMCC STB（移动机顶盒）软探针上报，
//   并从 HTTP body 中填充 StbRecord。
//
// 识别条件（满足任意一条即认为是STB上报）：
//   1. URL 中包含 "/family/"
//   2. User-Agent 中包含 "SoftDetector" 或 "softprobe"
//   3. JSON body 中包含 "deviceInfo" AND ("manufacturer" 字段
//      值为 "CMDC"/"SKYWORTH"/"HISENSE"/"CHANGHONG"/"HUAWEI")
//   4. JSON body 中同时包含 "tcpConnectInfo" 和 "stbRunTime"
// ─────────────────────────────────────────────────────────
class StbDetector
{
public:
	// 判断是否为STB上报（只看HTTP元数据，不解析body，快速路径）
	static bool isStbReport(const HttpSession &h);

	// 从 FlowEntry 的 HTTP 上下文填充 StbRecord
	// ts_us：包时间戳（微秒）
	// user_ip：用户IP（主机序，用于Radius账号查询）
	// user_mac / bras_mac：以太层MAC
	// server_ip：IP层目标IP（主机序）
	static bool buildRecord(const HttpSession &h,
							uint64_t ts_us,
							uint64_t user_mac,
							uint32_t server_ip,
							const char *user_account,
							StbRecord &out);

private:
	// 检查JSON body中是否包含STB特征字段
	static bool hasStbJsonFeature(const char *body, uint32_t len);

	// 从JSON提取 deviceInfo.macaddress 作为MAC
	// 格式："ac:bb:61:9f:10:90" → uint64
	static uint64_t extractMacFromJson(const char *body, uint32_t len);
};