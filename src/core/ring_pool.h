#pragma once
#include <rte_ring.h>
#include <rte_malloc.h>
#include <string>
#include <vector>
#include <stdexcept>
#include "../../include/common.h"

// ─────────────────────────────────────────────
// rte_ring 统一管理池
// 封装创建/查找/销毁，避免到处手写 rte_ring_create
// ─────────────────────────────────────────────
class RingPool
{
public:
	static RingPool &instance()
	{
		static RingPool inst;
		return inst;
	}

	// 创建单生产者单消费者环（SPSC，性能最优）
	struct rte_ring *createSpsc(const std::string &name,
								uint32_t size,
								int socket_id = SOCKET_ID_ANY)
	{
		auto *r = rte_ring_create(name.c_str(), size,
								  socket_id,
								  RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (!r)
			throw std::runtime_error(
				"rte_ring_create failed: " + name);
		rings_.push_back(r);
		return r;
	}

	// 创建多生产者单消费者环（多个Rx线程→同一消费者）
	struct rte_ring *createMpsc(const std::string &name,
								uint32_t size,
								int socket_id = SOCKET_ID_ANY)
	{
		auto *r = rte_ring_create(name.c_str(), size,
								  socket_id,
								  RING_F_SC_DEQ);
		if (!r)
			throw std::runtime_error(
				"rte_ring_create failed: " + name);
		rings_.push_back(r);
		return r;
	}

	// 按名称查找
	struct rte_ring *find(const std::string &name)
	{
		return rte_ring_lookup(name.c_str());
	}

	// 批量创建 Worker 环（命名规则：prefix_0, prefix_1, ...）
	std::vector<struct rte_ring *> createWorkerRings(
		const std::string &prefix,
		uint16_t count,
		uint32_t size = RING_SIZE,
		int socket_id = SOCKET_ID_ANY)
	{
		std::vector<struct rte_ring *> result;
		result.reserve(count);
		for (uint16_t i = 0; i < count; ++i)
		{
			result.push_back(createSpsc(
				prefix + "_" + std::to_string(i),
				size, socket_id));
		}
		return result;
	}

	// 销毁所有环（shutdown时调用）
	void destroyAll()
	{
		for (auto *r : rings_)
			rte_ring_free(r);
		rings_.clear();
	}

	// 查看环的填充率（用于Monitor监控反压）
	float fillRate(struct rte_ring *r) const
	{
		return (float)rte_ring_count(r) /
			   (float)rte_ring_get_capacity(r);
	}

private:
	RingPool() = default;
	std::vector<struct rte_ring *> rings_;
};