#include "udp_session.h"
#include <cstring>
#include <arpa/inet.h>

void UdpSessionHandler::onPacket(
	UdpSession &sess,
	const uint8_t *payload,
	uint32_t payload_len,
	uint32_t ip_total,
	uint64_t ts_us,
	bool is_upstream,
	uint16_t src_port,
	uint16_t dst_port,
	uint8_t traffic_type)
{
	if (sess.create_us == 0)
		sess.create_us = ts_us;
	sess.last_us = ts_us;

	if (is_upstream)
	{
		sess.ul_bytes += ip_total;
		sess.ul_pkts++;
	}
	else
	{
		sess.dl_bytes += ip_total;
		sess.dl_pkts++;
		sess.received_pkts++;

		// 尝试RTP序号解析（视频/直播流量）
		if (traffic_type >= 2 && payload_len >= 12)
		{
			uint16_t rtp_seq = 0;
			if (tryParseRtpSeq(payload, payload_len, rtp_seq))
			{
				if (!sess.rtp_initialized)
				{
					sess.last_rtp_seq = rtp_seq;
					sess.rtp_initialized = true;
					sess.expected_pkts = 1;
				}
				else
				{
					uint16_t expected = sess.last_rtp_seq + 1;
					uint16_t diff = rtp_seq - expected;
					if (diff > 0 && diff < 1000)
					{
						// 序号跳跃：有丢包
						sess.loss_count += diff;
						sess.expected_pkts += diff + 1;
					}
					else
					{
						sess.expected_pkts++;
					}
					sess.last_rtp_seq = rtp_seq;
				}
			}
		}
	}
}

bool UdpSessionHandler::tryParseRtpSeq(const uint8_t *payload,
									   uint32_t len,
									   uint16_t &seq_out)
{
	if (len < 12)
		return false;
	// RTP首字节：V(2)|P|X|CC(4)，版本必须为2（0x80开头）
	if ((payload[0] & 0xC0) != 0x80)
		return false;
	// 序号在字节2-3
	seq_out = (uint16_t)((payload[2] << 8) | payload[3]);
	return true;
}

void UdpSessionHandler::buildRecord(
	const UdpSession &sess,
	const FlowKey &key,
	uint8_t traffic_type,
	uint32_t ndpi_proto,
	UdpStreamRecord &out) const
{
	memset(&out, 0, sizeof(out));
	out.start_time = sess.create_us;
	out.user_ip = key.user_ip;
	out.server_ip = key.server_ip;
	out.user_port = key.user_port;
	out.server_port = key.server_port;
	out.ndpi_app_proto = ndpi_proto;
	out.traffic_type = traffic_type;
	out.expected_pkts = sess.expected_pkts;
	out.received_pkts = sess.received_pkts;
	out.loss_rate = sess.lossRate();
	out.duration_ms = sess.durationMs();
}