#pragma once

#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_ether.h>
#include <rte_byteorder.h>

#include <vector>
#include <cstdint>
#include <atomic>

#include "../../include/common.h"

// ─────────────────────────────────────────────────────────
// 分流配置
// ─────────────────────────────────────────────────────────
struct DispatchConfig
{
	uint32_t bras_network = 0; // 主机序
	uint32_t bras_netmask = 0;
	std::vector<uint32_t> radius_server_ips; // 主机序
	uint16_t radius_port = 1812;
	uint16_t nb_worker_queues = 1;
};

// ─────────────────────────────────────────────────────────
// FlowDispatcher
//
// RxThread 调用 dispatchBurst()，内部完成：
//   ① 解析以太头 EtherType
//   ② 识别 Radius / PPPoE / 用户流量
//   ③ enqueue 到对应 rte_ring
//   ④ 环满时 free mbuf（计入 drop 统计）
//
// 线程安全：
//   - dispatchBurst() 由单个 RxThread 调用（SPSC ring）
//   - 统计计数器用 relaxed 原子操作
// ─────────────────────────────────────────────────────────
class FlowDispatcher
{
public:
	explicit FlowDispatcher(const DispatchConfig &cfg);
	~FlowDispatcher() = default;

	// ── Ring 注册（main.cpp 调用，启动前完成）────────────
	void setRadiusRing(struct rte_ring *r) { radius_ring_ = r; }
	void setPPPoERing(struct rte_ring *r) { pppoe_ring_ = r; }
	void setWorkerRings(const std::vector<struct rte_ring *> &rings)
	{
		worker_rings_ = rings;
	}

	// ── 核心分发接口（RxThread 调用）─────────────────────
	// mbufs: 收到的包数组
	// nb:    包数量
	// 返回：被丢弃的包数（ring满）
	uint16_t dispatchBurst(struct rte_mbuf **mbufs, uint16_t nb);

	// ── 统计（Monitor 线程只读）──────────────────────────
	uint64_t getRadiusCount() const
	{
		return stat_radius_.load(std::memory_order_relaxed);
	}
	uint64_t getPPPoECount() const
	{
		return stat_pppoe_.load(std::memory_order_relaxed);
	}
	uint64_t getUserCount() const
	{
		return stat_user_.load(std::memory_order_relaxed);
	}
	uint64_t getDropCount() const
	{
		return stat_drop_.load(std::memory_order_relaxed);
	}

private:
	// ── 包分类 ───────────────────────────────────────────
	PktType classify(struct rte_mbuf *mbuf) const;

	// ── Worker 队列选择（RSS哈希或软件哈希）─────────────
	uint16_t selectWorker(struct rte_mbuf *mbuf) const;

	// ── 工具：IP是否为Radius服务器 ───────────────────────
	bool isRadiusServer(uint32_t ip) const;

	// ── 配置 ─────────────────────────────────────────────
	DispatchConfig cfg_;

	struct rte_ring *radius_ring_ = nullptr;
	struct rte_ring *pppoe_ring_ = nullptr;
	std::vector<struct rte_ring *> worker_rings_;

	// ── 统计 ─────────────────────────────────────────────
	std::atomic<uint64_t> stat_radius_{0};
	std::atomic<uint64_t> stat_pppoe_{0};
	std::atomic<uint64_t> stat_user_{0};
	std::atomic<uint64_t> stat_drop_{0};
};