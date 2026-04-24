#pragma once
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <vector>
#include <string>

struct DpdkPortConfig
{
	uint16_t port_id;
	uint16_t nb_rx_queues;
	uint16_t nb_tx_queues; // 采集模式通常0
	uint16_t rx_desc;	   // 建议4096
	bool promiscuous;
	uint32_t mbuf_pool_size; // 建议 256K * nb_queue
};

class DpdkEngine
{
public:
	static DpdkEngine &instance();

	// 初始化EAL + 网口
	int init(int argc, char **argv,
			 const std::vector<DpdkPortConfig> &ports);

	// 获取每个队列的mbuf pool
	struct rte_mempool *getMbufPool(uint16_t port_id, uint16_t queue_id);

	// 获取全局统计
	void collectStats(uint16_t port_id, rte_eth_stats &stats);

	// 停止
	void shutdown();

	// 禁止拷贝
	DpdkEngine(const DpdkEngine &) = delete;
	DpdkEngine &operator=(const DpdkEngine &) = delete;

private:
	DpdkEngine() = default;

	int configPort(const DpdkPortConfig &cfg);

	std::vector<struct rte_mempool *> mbuf_pools_; // 按 port*MAX_Q+queue 索引
	static constexpr uint16_t MAX_QUEUES = 32;
};