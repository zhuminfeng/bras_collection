#pragma once
#include <cstdint>
#include <cstring>

// ─────────────────────────────────────────────────────────
// HTTP DCS 记录结构
// 字段顺序与输出顺序严格对应，共59个字段
// ─────────────────────────────────────────────────────────
struct HttpRecord
{

	// ── 时间 ──────────────────────────────────────────────
	uint32_t hour_round_time; // 整点小时时间戳(秒)
	uint32_t min_round_time;  // 整分钟时间戳(秒)
	double start_time;		  // 会话开始时间(秒,精确到微秒)

	// ── 用户标识 ──────────────────────────────────────────
	char user_account[256]; // 用户账号（Radius获取）
	uint64_t user_mac_addr; // 用户MAC（6字节，存为uint64）
	uint64_t bras_mac_addr; // BRAS MAC
	uint32_t user_ip;		// 用户IP（网络序转主机序整数）
	uint32_t server_ip;		// 服务器IP
	uint16_t user_port;
	uint16_t server_port;

	// ── HTTP语义 ──────────────────────────────────────────
	// request_type: 1=GET 2=POST 3=CONNECT 4=OPTIONS
	//               5=HEAD 6=PUT 7=DELETE 8=TRACE
	uint8_t request_type;
	uint16_t status_code;		   // HTTP响应码，0=无响应
	uint32_t host_hash;			   // 域名Hash（MurmurHash32）
	char host_name[256];		   // 域名
	char cpe_model[256];		   // 终端型号
	char cpe_version[32];		   // 终端版本号
	char user_agent[256];		   // User-Agent
	char client_content_type[256]; // 请求Content-Type
	char server_content_type[256]; // 响应Content-Type
	char url[768];				   // URL（最大768字节）
	uint32_t response_interval;	   // 首响应时延(ms)

	// ── TCP握手与会话状态 ─────────────────────────────────
	// handshake_status / socket_status:
	//   0=成功 1=服务器无响应 2=用户侧无响应
	//   3=用户侧复位 4=服务器复位 5=解码异常 6=初始状态
	uint8_t handshake_status;
	uint8_t socket_status;
	uint8_t traffic_type; // 0=未识别 1=游戏 2=视频 3=直播
	uint32_t duration;	  // 会话时长(ms)

	// ── 流量统计 ──────────────────────────────────────────
	uint32_t ul_traffic;	  // 上行流量(bytes，含IP/TCP头)
	uint32_t dl_traffic;	  // 下行流量
	uint32_t http_ul_payload; // 上行HTTP payload(不含头)
	uint32_t http_dl_payload; // 下行HTTP payload

	// ── RTT/抖动 ─────────────────────────────────────────
	uint16_t server_rtt_count;
	uint32_t server_rtt_sum; // ms
	uint32_t user_rtt_count;
	uint32_t user_rtt_sum;
	uint32_t user_jitter_sum;	// ms
	uint32_t server_jitter_sum; // ms

	// ── 丢包 ──────────────────────────────────────────────
	uint32_t server_loss; // 服务器侧丢包数
	uint32_t user_loss;	  // 用户侧丢包数

	// ── 包计数 ────────────────────────────────────────────
	uint32_t ul_packets;
	uint32_t dl_packets;
	uint8_t user_launch;		// 1=用户发起 0=外部发起
	uint32_t dl_repeat_packets; // 下行重复包数

	// ── 握手RTT ───────────────────────────────────────────
	uint16_t hs_user_rtt;	// ms
	uint16_t hs_server_rtt; // ms

	// ── 有效会话（带payload的包）─────────────────────────
	uint32_t eff_duration;	 // ms
	uint32_t eff_ul_traffic; // bytes
	uint32_t eff_dl_traffic; // bytes
	uint32_t eff_ul_packets;
	uint32_t eff_dl_packets;

	// ── 移动网络扩展字段（固网场景填0）─────────────────────
	uint32_t isdn1;
	uint32_t isdn2;
	uint32_t imsi1;
	uint32_t imsi2;
	uint32_t imei1;
	uint32_t imei2;
	uint32_t cpe_mac_addr1;
	uint32_t cpe_mac_addr2;

	// ── 乱序统计 ──────────────────────────────────────────
	uint32_t uplink_disorder_cnt;
	uint32_t downlink_disorder_cnt;

	// ── 补充UA ────────────────────────────────────────────
	char second_user_agent[64];

	// ── 构造：全部清零，字符串默认"NONE" ─────────────────
	HttpRecord()
	{
		memset(this, 0, sizeof(*this));
		memcpy(user_account, "NONE", 4);
		memcpy(host_name, "NONE", 4);
		memcpy(cpe_model, "NONE", 4);
		memcpy(cpe_version, "NONE", 4);
		memcpy(user_agent, "NONE", 4);
		memcpy(client_content_type, "NONE", 4);
		memcpy(server_content_type, "NONE", 4);
		memcpy(url, "NONE", 4);
		memcpy(second_user_agent, "NONE", 4);
	}
};