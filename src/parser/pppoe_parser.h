#pragma once
#include <cstdint>
#include <cstring>
// PcapPlusPlus
#include <Packet.h>
#include <EthLayer.h>
#include <PPPoELayer.h>

// PPPoE 事件类型
enum class PPPoEEventType : uint8_t
{
	UNKNOWN = 0,
	PADI = 1,	 // 发现请求
	PADO = 2,	 // 发现应答
	PADR = 3,	 // 会话请求
	PADS = 4,	 // 会话确认
	PADT = 5,	 // 终止
	SESSION = 6, // 数据会话帧
};

struct PPPoERecord
{
	uint64_t event_time;	// 微秒
	uint8_t event_type;		// PPPoEEventType
	uint64_t client_mac;	// 客户端MAC
	uint64_t server_mac;	// AC/BRAS MAC
	uint16_t session_id;	// PPPoE Session ID
	char ac_name[64];		// Access Concentrator名称
	char service_name[64];	// 服务名
	char user_account[256]; // PPP协商用户名（如有）
};

// ─────────────────────────────────────────────
// PPPoE 信令解析器（使用PcapPlusPlus）
// 只解析PPPoE Discovery阶段（0x8863）
// Session阶段（0x8864）的IP包由Worker线程处理
// ─────────────────────────────────────────────
class PPPoEParser
{
public:
	// 解析成功返回true
	bool parse(const pcpp::Packet &pkt,
			   uint64_t ts_us,
			   PPPoERecord &out);

private:
	// 从PPPoE Discovery的Tag中提取字符串
	static std::string extractTag(pcpp::PPPoEDiscoveryLayer *layer,
								  pcpp::PPPoEDiscoveryLayer::PPPoETagTypes type);

	// MAC bytes → uint64
	static uint64_t mac2u64(const uint8_t *m)
	{
		return ((uint64_t)m[0] << 40) | ((uint64_t)m[1] << 32) |
			   ((uint64_t)m[2] << 24) | ((uint64_t)m[3] << 16) |
			   ((uint64_t)m[4] << 8) | (uint64_t)m[5];
	}
};