#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <memory>
#include <thread>

#include "../../include/common.h"
#include "../utils/stats.h"
#include "../utils/lock_free_queue.h"
#include "signal_queues.h" // SignalOutputQueues
#include "../record/http_record.h"
#include "../record/record_types.h"
#include "../record/onu_record.h"
#include "../output/raw_file_manager.h"

// 前向声明
struct WorkerOutputQueues;

// ─────────────────────────────────────────────────────────
// OutputThread 配置
// ─────────────────────────────────────────────────────────
struct OutputThreadConfig
{
	std::string raw_dir = "./raw";
	std::string collector_id = "collector0";
	uint32_t rotate_interval = 60; // 秒
	uint32_t drain_batch = 1024;   // 每轮最多消费条数
	uint32_t idle_sleep_us = 1000; // 空转休眠微秒
};

// ★ 队列水位快照（供 MonitorThread 查询）
struct QueueDepth
{
	uint64_t http_total = 0; // 所有 worker http_q 之和
	uint64_t tcp_total = 0;
	uint64_t dns_total = 0;
	uint64_t udp_total = 0;
	uint64_t radius = 0; // 所有 signal radius_q 之和
	uint64_t pppoe = 0;
	uint64_t onu_total = 0;
	uint64_t ping_total = 0;
	uint64_t stb_total = 0;
};

// ─────────────────────────────────────────────────────────
// OutputThread
//
// 职责：
//   1. 从所有 WorkerThread 输出队列消费记录（TCP/HTTP/ONU/DNS/UDP）
//   2. 从 RadiusThread 输出队列消费记录（Radius/PPPoE）
//   3. 序列化写入 DCS 文件（通过 RawFileManager）
//   4. 每 rotate_interval 秒触发文件轮转
//
// 线程模型：
//   独立 std::thread，单线程串行写文件
// ─────────────────────────────────────────────────────────
class OutputThread : NonCopyable
{
public:
	explicit OutputThread(const OutputThreadConfig &cfg);
	~OutputThread();

	// ── 注册队列（start() 前调用）────────────────────────
	// WorkerThread 队列（可注册多个 Worker）
	void registerWorkerQueues(WorkerOutputQueues *wq);

	// RadiusThread 队列（通常只有一个）
	void registerSignalQueues(SignalOutputQueues *sq);

	// ── 生命周期控制 ─────────────────────────────────────
	void start();
	void stop();
	void join();

	bool isRunning() const
	{
		return state_.load(std::memory_order_relaxed) == ThreadState::RUNNING;
	}

	// ── 统计 ─────────────────────────────────────────────
	uint64_t writtenTcp() const
	{
		return stat_tcp_.load(std::memory_order_relaxed);
	}
	uint64_t writtenHttp() const
	{
		return stat_http_.load(std::memory_order_relaxed);
	}
	uint64_t writtenOnu() const
	{
		return stat_onu_.load(std::memory_order_relaxed);
	}
	uint64_t writtenPing() const
	{
		return stat_ping_.load(std::memory_order_relaxed);
	}
	uint64_t writtenRadius() const
	{
		return stat_radius_.load(std::memory_order_relaxed);
	}
	uint64_t writtenPppoe() const
	{
		return stat_pppoe_.load(std::memory_order_relaxed);
	}
	uint64_t writtenDns() const
	{
		return stat_dns_.load(std::memory_order_relaxed);
	}
	uint64_t writtenUdp() const
	{
		return stat_udp_.load(std::memory_order_relaxed);
	}
	uint64_t writtenStb() const
	{
		return stat_stb_.load(std::memory_order_relaxed);
	}
	uint64_t droppedTotal() const
	{
		return stat_drop_.load(std::memory_order_relaxed);
	}

	QueueDepth getQueueDepth() const;

	// ★ 伪 stats() 接口：返回一个只读统计对象供 Monitor 兼容
	// （Monitor 只用 output_records，用 writtenTcp 等之和代替）
	struct OutputStats
	{
		std::atomic<uint64_t> output_records{0};
	};
	// 注意：不额外维护 OutputStats 对象，
	// 直接在 getOutputRecords() 中返回所有写入量之和
	uint64_t getOutputRecords() const
	{
		return stat_tcp_.load(std::memory_order_relaxed) + stat_http_.load(std::memory_order_relaxed) + stat_onu_.load(std::memory_order_relaxed) + stat_radius_.load(std::memory_order_relaxed) + stat_pppoe_.load(std::memory_order_relaxed) + stat_dns_.load(std::memory_order_relaxed) + stat_udp_.load(std::memory_order_relaxed) + stat_ping_.load(std::memory_order_relaxed) + stat_stb_.load(std::memory_order_relaxed);
	}

private:
	// ── 主循环 ───────────────────────────────────────────
	void run();

	// ── 队列消费 ─────────────────────────────────────────
	uint32_t drainWorkerQueues(WorkerOutputQueues *wq);
	uint32_t drainSignalQueues(SignalOutputQueues *sq);

	// ── 各协议写入 ────────────────────────────────────────
	void writeTcpRecord(const TcpSessionRecord &r);
	void writeHttpRecord(const HttpRecord &r);
	void writeOnuRecord(const OnuRecord &r);
	void writePingRecord(const PingRecord &r);
	void writeRadiusRecord(const RadiusRecord &r);
	void writePppoeRecord(const PPPoERecord &r);
	void writeDnsRecord(const DnsRecord &r);
	void writeUdpRecord(const UdpStreamRecord &r);
	void writeStbRecord(const StbRecord &r);

	// ── 文件轮转 ─────────────────────────────────────────
	void rotateIfNeeded(uint64_t now_us);

	// ── 配置与状态 ────────────────────────────────────────
	OutputThreadConfig cfg_;
	std::unique_ptr<RawFileManager> file_manager_;

	std::thread thread_;
	std::atomic<bool> running_{false};
	std::atomic<ThreadState> state_{ThreadState::IDLE};

	// Worker 队列列表
	static constexpr uint16_t MAX_WORKERS = 64;
	WorkerOutputQueues *worker_queues_[MAX_WORKERS] = {};
	std::atomic<uint16_t> worker_count_{0};

	// Signal 队列列表
	static constexpr uint8_t MAX_SIGNAL_QUEUES = 4;
	SignalOutputQueues *signal_queues_[MAX_SIGNAL_QUEUES] = {};
	std::atomic<uint8_t> signal_count_{0};

	// 上次轮转的时间戳
	uint32_t last_rotate_min_ = 0;

	// ── 统计计数器 ────────────────────────────────────────
	std::atomic<uint64_t> stat_tcp_{0};
	std::atomic<uint64_t> stat_http_{0};
	std::atomic<uint64_t> stat_onu_{0};
	std::atomic<uint64_t> stat_ping_{0};
	std::atomic<uint64_t> stat_radius_{0};
	std::atomic<uint64_t> stat_pppoe_{0};
	std::atomic<uint64_t> stat_dns_{0};
	std::atomic<uint64_t> stat_udp_{0};
	std::atomic<uint64_t> stat_stb_{0};
	std::atomic<uint64_t> stat_drop_{0};
};
