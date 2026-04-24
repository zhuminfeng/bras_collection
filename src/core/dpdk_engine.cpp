#include "dpdk_engine.h"
#include <rte_ethdev.h>
#include <rte_log.h>
#include <stdexcept>
#include <cstring>

// ─────────────────────────────────────────────────────────
// ConnectX-5 专用：对称RSS哈希键
// 对称键保证 (srcIP,dstIP) 和 (dstIP,srcIP) 落到同一队列
// mlx5 原生支持 Toeplitz 对称哈希
// ─────────────────────────────────────────────────────────
static const uint8_t MLX5_SYM_RSS_KEY[40] = {
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
	0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A};

DpdkEngine &DpdkEngine::instance()
{
	static DpdkEngine inst;
	return inst;
}

int DpdkEngine::init(int argc, char **argv,
					 const std::vector<DpdkPortConfig> &ports)
{
	// 初始化EAL
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
	{
		throw std::runtime_error("rte_eal_init failed");
	}

	mbuf_pools_.resize(ports.size() * MAX_QUEUES, nullptr);

	for (auto &cfg : ports)
	{
		if (configPort(cfg) != 0)
		{
			throw std::runtime_error("Port config failed: " + std::to_string(cfg.port_id));
		}
	}
	return 0;
}

int DpdkEngine::configPort(const DpdkPortConfig &cfg)
{
	uint16_t port_id = cfg.port_id;

	// ── 查询网卡能力 ──────────────────────────────────────
	struct rte_eth_dev_info dev_info{};
	rte_eth_dev_info_get(port_id, &dev_info);

	// 打印确认是 mlx5
	RTE_LOG(INFO, USER1, "Port %u: driver=%s, max_rx_queues=%u\n",
			port_id, dev_info.driver_name, dev_info.max_rx_queues);

	// ── mbuf pool 创建（mlx5要求内存连续，使用1G大页）────
	for (uint16_t q = 0; q < cfg.nb_rx_queues; ++q)
	{
		char name[64];
		snprintf(name, sizeof(name), "mbuf_p%d_q%d", port_id, q);

		// 100G场景：pool_size需要更大，建议512K/队列
		// cache_size=512 减少跨核内存访问
		auto *pool = rte_pktmbuf_pool_create(
			name,
			524288, // 512K mbufs/队列
			512,	// cache_size
			0,		// priv_size（可存PktDescriptor，避免额外malloc）
			// mlx5 mprq模式下buf_size可以小一些，stride管理
			RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_eth_dev_socket_id(port_id) // NUMA绑定！
		);
		if (!pool)
		{
			RTE_LOG(ERR, USER1, "mbuf pool create failed: %s\n",
					rte_strerror(rte_errno));
			return -1;
		}
		mbuf_pools_[port_id * MAX_QUEUES + q] = pool;
	}

	// ── 端口配置 ─────────────────────────────────────────
	struct rte_eth_conf port_conf{};
	memset(&port_conf, 0, sizeof(port_conf));

	port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;

	// ConnectX-5 支持的 RSS 类型（比 Intel 更丰富）
	port_conf.rx_adv_conf.rss_conf.rss_key =
		const_cast<uint8_t *>(MLX5_SYM_RSS_KEY);
	port_conf.rx_adv_conf.rss_conf.rss_key_len = 40;
	port_conf.rx_adv_conf.rss_conf.rss_hf =
		RTE_ETH_RSS_IP |
		RTE_ETH_RSS_TCP |
		RTE_ETH_RSS_UDP |
		RTE_ETH_RSS_IPV6 |		 // mlx5 支持 IPv6 RSS
		RTE_ETH_RSS_L3_SRC_ONLY; // 可选：仅按SRC IP分流

	// ── 关键：启用硬件RX offload ─────────────────────────
	port_conf.rxmode.offloads =
		RTE_ETH_RX_OFFLOAD_CHECKSUM |	// 硬件校验和验证
		RTE_ETH_RX_OFFLOAD_VLAN_STRIP | // 硬件剥离VLAN（含QinQ）
		RTE_ETH_RX_OFFLOAD_RSS_HASH |	// 硬件RSS哈希写入mbuf
		RTE_ETH_RX_OFFLOAD_SCATTER;		// 支持多段mbuf（jumbo frame）

	// 启用硬件时间戳（ConnectX-5核心优势）
	// 需要先同步PTP：ptp4l -i ens1f0 -m
	if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TIMESTAMP)
	{
		port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_TIMESTAMP;
		hw_timestamp_enabled_ = true;
		RTE_LOG(INFO, USER1, "Port %u: HW timestamp enabled\n", port_id);
	}

	// 巨帧（jumbo frame）支持
	port_conf.rxmode.max_lro_pkt_size = 9600;

	if (rte_eth_dev_configure(port_id,
							  cfg.nb_rx_queues,
							  cfg.nb_tx_queues,
							  &port_conf) < 0)
	{
		return -1;
	}

	// ── 调整 RX 描述符数量 ───────────────────────────────
	uint16_t nb_rx_desc = cfg.rx_desc;
	uint16_t nb_tx_desc = 0;
	rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rx_desc, &nb_tx_desc);

	// ── 配置每个 RX 队列 ─────────────────────────────────
	for (uint16_t q = 0; q < cfg.nb_rx_queues; ++q)
	{
		struct rte_eth_rxconf rxconf = dev_info.default_rxconf;
		// 使用网卡推荐的默认配置，不手动设置阈值
		// mlx5 的最优阈值与 Intel 不同

		// 继承port级别的offload设置到队列
		rxconf.offloads = port_conf.rxmode.offloads;

		if (rte_eth_rx_queue_setup(
				port_id, q, nb_rx_desc,
				rte_eth_dev_socket_id(port_id),
				&rxconf,
				mbuf_pools_[port_id * MAX_QUEUES + q]) < 0)
		{
			return -1;
		}
	}

	if (rte_eth_dev_start(port_id) < 0)
		return -1;

	if (cfg.promiscuous)
	{
		rte_eth_promiscuous_enable(port_id);
	}

	return 0;
}

struct rte_mempool *DpdkEngine::getMbufPool(uint16_t port_id, uint16_t queue_id)
{
	return mbuf_pools_[port_id * MAX_QUEUES + queue_id];
}

void DpdkEngine::collectStats(uint16_t port_id, rte_eth_stats &stats)
{
	rte_eth_stats_get(port_id, &stats);
}

void DpdkEngine::shutdown()
{
	uint16_t port_id;
	RTE_ETH_FOREACH_DEV(port_id)
	{
		rte_eth_dev_stop(port_id);
		rte_eth_dev_close(port_id);
	}
	rte_eal_cleanup();
}