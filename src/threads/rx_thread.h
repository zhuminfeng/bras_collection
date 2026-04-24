#pragma once

#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_ring.h>

#include <atomic>
#include <cstdint>
#include <cstring>

#include "../../include/common.h"
#include "../utils/stats.h"

// 前向声明
class FlowDispatcher;

// ─────────────────────────────────────────────────────────
// RxThread 配置
// ─────────────────────────────────────────────────────────
struct RxThreadConfig
{
	uint16_t port_id = 0;
	uint16_t queue_id = 0;
	uint32_t lcore_id = 0;
	uint32_t burst_size = BURST_SIZE; // common.h 定义：64
	FlowDispatcher *dispatcher = nullptr;

	// 硬件时间戳：ConnectX-5 可用，Intel igb/ixgbe 不支持
	bool hw_timestamp = false;

	// 空转自适应休眠阈值（连续空转次数）
	uint32_t idle_pause_thresh = 10000;	 // 低于此用rte_pause
	uint32_t idle_sleep_thresh = 100000; // 高于此用usleep
	uint32_t idle_sleep_us = 10;		 // usleep时长
};

// ─────────────────────────────────────────────────────────
// RxThread
//
// 职责：
//   1. rte_eth_rx_burst 从指定队列批量收包
//   2. 填写 mbuf->timestamp（硬件或TSC）
//   3. 调用 FlowDispatcher 将包分发到各协议环
//   4. 更新 ThreadStats
//
// 线程模型：
//   - 每个 RxThread 绑定一个 DPDK lcore
//   - 每个 lcore 绑定一个 NIC 队列（1:1）
//   - 不做任何包解析，只做分发
//
// 时间戳策略：
//   hw_timestamp=true  → 使用 mbuf->ol_flags 中的硬件时间戳
//                         （需要端口配置 RTE_ETH_RX_OFFLOAD_TIMESTAMP）
//   hw_timestamp=false → 使用 rte_rdtsc() 转换为纳秒
//                         精度约 1μs，100G场景足够
// ─────────────────────────────────────────────────────────
class RxThread : NonCopyable
{
public:
	explicit RxThread(const RxThreadConfig &cfg);
	~RxThread() = default;

	// ── DPDK lcore 入口 ───────────────────────────────────
	static int lcoreEntry(void *arg);

	// ── 生命周期控制 ─────────────────────────────────────
	void stop()
	{
		running_.store(false, std::memory_order_relaxed);
	}

	bool isRunning() const
	{
		return state_.load(std::memory_order_relaxed) == ThreadState::RUNNING;
	}

	// ── 统计访问 ─────────────────────────────────────────
	ThreadStats &stats() { return stats_; }
	const ThreadStats &stats() const { return stats_; }

	// ── 配置访问（只读）─────────────────────────────────
	uint16_t portId() const { return cfg_.port_id; }
	uint16_t queueId() const { return cfg_.queue_id; }
	uint32_t lcoreId() const { return cfg_.lcore_id; }

private:
	// ── 主循环 ───────────────────────────────────────────
	void run();

	// ── 时间戳填充 ───────────────────────────────────────
	// 将当前时间（纳秒）写入 mbuf->timestamp
	// 对一个burst的所有包使用同一个时间戳（减少rdtsc调用次数）
	void fillTimestamps(struct rte_mbuf **mbufs,
						uint16_t nb,
						uint64_t ts_ns);

	// TSC → 纳秒转换
	// 在 run() 开始时初始化换算系数，避免循环内除法
	void initTscConvert();
	inline uint64_t tscToNs(uint64_t tsc) const
	{
		// ts_ns = tsc * (1e9 / tsc_hz)
		// 用定点数乘法避免浮点：ts_ns = tsc * tsc_mult >> tsc_shift
		return ((__uint128_t)tsc * tsc_mult_) >> tsc_shift_;
	}

	// ── 成员变量 ─────────────────────────────────────────
	RxThreadConfig cfg_;
	std::atomic<bool> running_{true};
	std::atomic<ThreadState> state_{ThreadState::IDLE};
	ThreadStats stats_;

	// TSC换算参数（避免循环内浮点运算）
	uint64_t tsc_mult_ = 0;
	uint32_t tsc_shift_ = 0;
	uint64_t tsc_hz_ = 0;

	// NIC 硬件时间戳能力缓存
	bool hw_ts_capable_ = false;
};