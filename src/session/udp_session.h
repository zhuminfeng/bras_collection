#pragma once
#include <cstdint>
#include "../record/record_types.h"
#include "../parser/ndpi_analyzer.h"

// UDP流状态（附在FlowEntry上）
struct UdpSession
{
	uint64_t create_us = 0;
	uint64_t last_us = 0;

	uint64_t ul_bytes = 0;
	uint64_t dl_bytes = 0;
	uint32_t ul_pkts = 0;
	uint32_t dl_pkts = 0;

	// 实时流质量（RTP类协议）
	uint32_t expected_pkts = 0; // 按RTP序号估算
	uint32_t received_pkts = 0;
	uint16_t last_rtp_seq = 0;
	bool rtp_initialized = false;

	// 统计
	uint32_t loss_count = 0;

	uint32_t durationMs() const
	{
		if (last_us <= create_us)
			return 0;
		return (uint32_t)((last_us - create_us) / 1000);
	}

	float lossRate() const
	{
		if (expected_pkts == 0)
			return 0.0f;
		return (float)loss_count / (float)expected_pkts;
	}
};

// ─────────────────────────────────────────────
// UDP会话处理器
// ─────────────────────────────────────────────
class UdpSessionHandler
{
public:
	// 处理一个UDP包，更新session状态
	// payload: UDP payload数据（RTP等）
	void onPacket(UdpSession &sess,
				  const uint8_t *payload,
				  uint32_t payload_len,
				  uint32_t ip_total,
				  uint64_t ts_us,
				  bool is_upstream,
				  uint16_t src_port,
				  uint16_t dst_port,
				  uint8_t traffic_type);

	// 从session构造输出记录
	void buildRecord(const UdpSession &sess,
					 const FlowKey &key,
					 uint8_t traffic_type,
					 uint32_t ndpi_proto,
					 UdpStreamRecord &out) const;

private:
	// 尝试解析RTP序号（用于丢包率计算）
	bool tryParseRtpSeq(const uint8_t *payload,
						uint32_t len,
						uint16_t &seq_out);
};