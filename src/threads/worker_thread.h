#pragma once

#include <rte_ring.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_ether.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <functional>
#include <unordered_map> // ★ ping session 跟踪

#include "../../include/common.h"
#include "../utils/stats.h"
#include "../session/flow_table.h"
#include "../session/tcp_session.h"
#include "../parser/ndpi_analyzer.h"
#include "../parser/cpe_detector.h"
#include "../parser/onu_parser.h"
#include "../record/http_record.h"
#include "../record/record_types.h"
#include "../record/onu_record.h"
#include "../record/ping_record.h"
#include "../utils/lock_free_queue.h"
#include "../record/stb_record.h"
#include "../parser/stb_detector.h"

class RawFileManager;

// ─────────────────────────────────────────────────────────
// Worker 输出队列（WorkerThread → OutputThread）
// ─────────────────────────────────────────────────────────
struct WorkerOutputQueues
{
	LockFreeQueue<HttpRecord> http_q{4096};
	LockFreeQueue<TcpSessionRecord> tcp_q{4096};
	LockFreeQueue<OnuRecord> onu_q{1024};
	LockFreeQueue<DnsRecord> dns_q{4096};
	LockFreeQueue<UdpStreamRecord> udp_q{4096};
	LockFreeQueue<PingRecord> ping_q{2048};
	LockFreeQueue<StbRecord> stb_q{512};

	WorkerOutputQueues() = default;
	WorkerOutputQueues(const WorkerOutputQueues &) = delete;
	WorkerOutputQueues &operator=(const WorkerOutputQueues &) = delete;
};

// ─────────────────────────────────────────────────────────
// WorkerThread 配置
// ─────────────────────────────────────────────────────────
struct WorkerThreadConfig
{
	struct rte_ring *ring = nullptr;
	WorkerOutputQueues *output_queues = nullptr;
	uint16_t worker_id = 0;
	uint32_t lcore_id = 0;

	uint32_t user_net = 0;
	uint32_t user_mask = 0;

	uint64_t flow_timeout_us = 120ULL * 1000000;

	char onu_url_prefix[64] = "/report";

	// ★ ICMP 会话超时（默认10秒等不到响应则输出）
	uint64_t ping_timeout_us = 10ULL * 1000000;
};

// ─────────────────────────────────────────────────────────
// 内部：ICMP Echo 待匹配条目
// ───────────────────���─────────────────────────────────────
struct PingSession
{
	uint32_t user_ip = 0;
	uint32_t server_ip = 0;
	uint64_t user_mac = 0;
	uint64_t bras_mac = 0;
	char user_account[256] = {};
	uint64_t request_us = 0; // 请求发出时间（微秒）
	uint16_t payload_size = 0;
	bool responded = false;
	uint32_t rtt_ms = 0; // 响应RTT（毫秒）
};

// ─────────────────────────────────────────────────────────
// WorkerThread
// ─────────────────────────────────────────────────────────
class WorkerThread : NonCopyable
{
public:
	using Config = WorkerThreadConfig;

	explicit WorkerThread(const Config &cfg);
	~WorkerThread() = default;

	static int lcoreEntry(void *arg);

	void stop()
	{
		running_.store(false, std::memory_order_relaxed);
	}

	bool isRunning() const
	{
		return state_.load(std::memory_order_relaxed) == ThreadState::RUNNING;
	}

	ThreadStats &stats() { return stats_; }
	const ThreadStats &stats() const { return stats_; }

	uint16_t workerId() const { return cfg_.worker_id; }
	uint32_t lcoreId() const { return cfg_.lcore_id; }

private:
	void run();

	void processTcpPacket(const uint8_t *raw,
						  uint32_t pkt_len,
						  const rte_ipv4_hdr *ip,
						  uint32_t ip_offset,
						  uint64_t ts_us,
						  bool is_upstream,
						  uint64_t src_mac,
						  uint64_t dst_mac,
						  FlowTable &flow_table);

	void processUdpPacket(const uint8_t *raw,
						  uint32_t pkt_len,
						  const rte_ipv4_hdr *ip,
						  uint32_t ip_offset,
						  uint64_t ts_us,
						  bool is_upstream);

	void processIcmpPacket(const uint8_t *raw,
						   uint32_t pkt_len,
						   const rte_ipv4_hdr *ip,
						   uint32_t ip_offset,
						   uint64_t ts_us,
						   bool is_upstream,
						   uint64_t src_mac,
						   uint64_t dst_mac);

	void onTcpFlowClose(FlowEntry &fe, uint64_t now_us);

	void buildAndOutputTcpRecord(FlowEntry &fe, uint64_t now_us);
	void buildAndOutputHttpRecord(FlowEntry &fe, uint64_t now_us);
	void buildAndOutputOnuRecord(FlowEntry &fe, uint64_t now_us);
	void buildAndOutputPingRecord(const PingSession &ps,
								  uint64_t now_us);
	void purgePingSessions(uint64_t now_us);
	void buildAndOutputStbRecord(FlowEntry &fe, uint64_t now_us);

	bool isUserIp(uint32_t ip) const
	{
		return (ip & cfg_.user_mask) ==
			   (cfg_.user_net & cfg_.user_mask);
	}

	static bool isHttpPort(uint16_t port)
	{
		return port == 80 || port == 8080 ||
			   port == 8000 || port == 8888 ||
			   port == 3128;
	}

	bool isOnuReport(const FlowEntry &fe) const;

	Config cfg_;
	struct rte_ring *ring_;
	WorkerOutputQueues *output_queues_;

	std::atomic<bool> running_{true};
	std::atomic<ThreadState> state_{ThreadState::IDLE};

	ThreadStats stats_;

	NdpiAnalyzer ndpi_;
	CpeDetector cpe_det_;
	OnuParser onu_parser_;

	// ★ ICMP Echo 请求追踪表
	// key = (user_ip[31:0]) ^ (icmp_id[15:0] << 32) ^ (icmp_seq[15:0] << 48)
	// 注意：单Worker线程，无锁安全
	std::unordered_map<uint64_t, PingSession> ping_sessions_;
	uint64_t last_ping_purge_us_ = 0;
};
