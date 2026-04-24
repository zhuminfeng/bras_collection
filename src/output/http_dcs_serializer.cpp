#include "http_dcs_serializer.h"
#include <cstdio>
#include <cstring>

// 宏简化：追加整数字段 + Tab
#define APPEND_U8(val)                                                     \
	do                                                                     \
	{                                                                      \
		pos += snprintf(buf + pos, buf_size - pos, "%u", (unsigned)(val)); \
		pos = tab(buf, pos);                                               \
	} while (0)

#define APPEND_U16(val)                                                    \
	do                                                                     \
	{                                                                      \
		pos += snprintf(buf + pos, buf_size - pos, "%u", (unsigned)(val)); \
		pos = tab(buf, pos);                                               \
	} while (0)

#define APPEND_U32(val)                                                    \
	do                                                                     \
	{                                                                      \
		pos += snprintf(buf + pos, buf_size - pos, "%u", (uint32_t)(val)); \
		pos = tab(buf, pos);                                               \
	} while (0)

#define APPEND_U64(val)                                                     \
	do                                                                      \
	{                                                                       \
		pos += snprintf(buf + pos, buf_size - pos, "%lu", (uint64_t)(val)); \
		pos = tab(buf, pos);                                                \
	} while (0)

#define APPEND_DBL(val)                                                    \
	do                                                                     \
	{                                                                      \
		pos += snprintf(buf + pos, buf_size - pos, "%.6f", (double)(val)); \
		pos = tab(buf, pos);                                               \
	} while (0)

#define APPEND_STR(str)                             \
	do                                              \
	{                                               \
		pos = appendStr(buf, pos, buf_size, (str)); \
		pos = tab(buf, pos);                        \
	} while (0)

// 最后一个字段不加Tab
#define APPEND_STR_LAST(str)                        \
	do                                              \
	{                                               \
		pos = appendStr(buf, pos, buf_size, (str)); \
	} while (0)

#define APPEND_U32_LAST(val)                                               \
	do                                                                     \
	{                                                                      \
		pos += snprintf(buf + pos, buf_size - pos, "%u", (uint32_t)(val)); \
	} while (0)

size_t HttpDcsSerializer::serialize(const HttpRecord &r,
									char *buf,
									size_t buf_size)
{
	size_t pos = 0;

	// ── 1. 时间 ─────────────────────────────────────────
	APPEND_U32(r.hour_round_time); // 整点小时时间戳
	APPEND_U32(r.min_round_time);  // 整分时间戳
	APPEND_DBL(r.start_time);	   // 会话开始时间（微秒精度）

	// ── 2. 用户标识 ──────────────────────────────────────
	APPEND_STR(r.user_account);	 // 用户账号（字符串）
	APPEND_U64(r.user_mac_addr); // 用户MAC（uint64）
	APPEND_U64(r.bras_mac_addr); // BRAS MAC（uint64）
	APPEND_U32(r.user_ip);		 // 用户IP（uint32）
	APPEND_U32(r.server_ip);	 // 服务器IP
	APPEND_U16(r.user_port);
	APPEND_U16(r.server_port);

	// ── 3. HTTP语义 ──────────────────────────────────────
	APPEND_U8(r.request_type);
	APPEND_U16(r.status_code);
	APPEND_U32(r.host_hash);
	APPEND_STR(r.host_name);
	APPEND_STR(r.cpe_model);
	APPEND_STR(r.cpe_version);
	APPEND_STR(r.user_agent);
	APPEND_STR(r.client_content_type);
	APPEND_STR(r.server_content_type);
	APPEND_STR(r.url);
	APPEND_U32(r.response_interval);

	// ── 4. 握手与会话状态 ────────────────────────────────
	APPEND_U8(r.handshake_status);
	APPEND_U8(r.socket_status);
	APPEND_U8(r.traffic_type);
	APPEND_U32(r.duration);

	// ── 5. 流量 ──────────────────────────────────────────
	APPEND_U32(r.ul_traffic);
	APPEND_U32(r.dl_traffic);
	APPEND_U32(r.http_ul_payload);
	APPEND_U32(r.http_dl_payload);

	// ── 6. RTT/抖动 ──────────────────────────────────────
	APPEND_U16(r.server_rtt_count);
	APPEND_U32(r.server_rtt_sum);
	APPEND_U32(r.user_rtt_count);
	APPEND_U32(r.user_rtt_sum);
	APPEND_U32(r.user_jitter_sum);
	APPEND_U32(r.server_jitter_sum);

	// ── 7. 丢包 ──────────────────────────────────────────
	APPEND_U32(r.server_loss);
	APPEND_U32(r.user_loss);

	// ── 8. 包计数 ────────────────────────────────────────
	APPEND_U32(r.ul_packets);
	APPEND_U32(r.dl_packets);
	APPEND_U8(r.user_launch);
	APPEND_U32(r.dl_repeat_packets);

	// ── 9. 握手RTT ───────────────────────────────────────
	APPEND_U16(r.hs_user_rtt);
	APPEND_U16(r.hs_server_rtt);

	// ── 10. 有效会话 ─────────────────────────────────────
	APPEND_U32(r.eff_duration);
	APPEND_U32(r.eff_ul_traffic);
	APPEND_U32(r.eff_dl_traffic);
	APPEND_U32(r.eff_ul_packets);
	APPEND_U32(r.eff_dl_packets);

	// ── 11. 移动扩展字段（固网填0）──────────────────────
	APPEND_U32(r.isdn1);
	APPEND_U32(r.isdn2);
	APPEND_U32(r.imsi1);
	APPEND_U32(r.imsi2);
	APPEND_U32(r.imei1);
	APPEND_U32(r.imei2);
	APPEND_U32(r.cpe_mac_addr1);
	APPEND_U32(r.cpe_mac_addr2);

	// ── 12. 乱序统计 ─────────────────────────────────────
	APPEND_U32(r.uplink_disorder_cnt);
	APPEND_U32(r.downlink_disorder_cnt);

	// ── 13. 补充UA（最后一个字段，不加Tab）──────────────
	APPEND_STR_LAST(r.second_user_agent);

	return pos;
}