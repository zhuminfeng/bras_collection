#include "rx_thread.h"

#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_branch_prediction.h>

#include <unistd.h>
#include <cstring>

#include "../core/flow_dispatcher.h"
#include <spdlog/spdlog.h>

// ─────────────────────────────────────────────────────────
// 构造
// ─────────────────────────────────────────────────────────
RxThread::RxThread(const RxThreadConfig &cfg)
	: cfg_(cfg)
{
	if (!cfg_.dispatcher)
		throw std::runtime_error("RxThread: dispatcher is null");

	// 检查网卡是否支持硬件时间戳
	struct rte_eth_dev_info dev_info{};
	rte_eth_dev_info_get(cfg_.port_id, &dev_info);
	hw_ts_capable_ =
		cfg_.hw_timestamp &&
		(dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TIMESTAMP);

	if (cfg_.hw_timestamp && !hw_ts_capable_)
	{
		spdlog::warn("[RxThread port={} q={}] hw_timestamp requested "
					 "but NIC does not support it, falling back to TSC",
					 cfg_.port_id, cfg_.queue_id);
	}
}

// ─────────────────────────────────────────────────────────
// DPDK lcore 入口
// ─────────────────────────────────────────────────────────
int RxThread::lcoreEntry(void *arg)
{
	auto *self = static_cast<RxThread *>(arg);
	self->run();
	return 0;
}

// ─────────────────────────────────────────────────────────
// TSC 换算系数初始化
//
// 目标：tsc → ns，避免循环内浮点除法
// 方法：预计算 mult 和 shift，使得：
//   ns = (tsc * mult) >> shift
//
// 参考 Linux kernel clocksource 的 cyc2ns 实现
// ─────────────────────────────────────────────────────────
void RxThread::initTscConvert()
{
	tsc_hz_ = rte_get_tsc_hz();

	// 选择 shift 使 mult 尽量大（精度高）但不溢出 uint64_t
	// mult = (1e9 << shift) / tsc_hz
	// 要求：mult * (最大tsc增量) < 2^64
	// 最大tsc增量取 2^32（约4秒，burst间隔远小于此）
	tsc_shift_ = 32;
	while (tsc_shift_ > 0)
	{
		__uint128_t mult =
			((__uint128_t)1000000000ULL << tsc_shift_) / tsc_hz_;
		if (mult <= UINT64_MAX)
		{
			tsc_mult_ = (uint64_t)mult;
			break;
		}
		--tsc_shift_;
	}

	spdlog::info("[RxThread port={} q={}] TSC: hz={} mult={} shift={}",
				 cfg_.port_id, cfg_.queue_id,
				 tsc_hz_, tsc_mult_, tsc_shift_);
}

// ─────────────────────────────────────────────────────────
// 时间戳填充
//
// hw_timestamp：直接使用 mbuf->timestamp（NIC写入，纳秒）
// TSC：对整个burst使用同一个时间戳（减少 rdtsc 调用次数）
//       单次burst耗时 < 1μs，误差可接受
// ─────────────────────────────────────────────────────────
void RxThread::fillTimestamps(struct rte_mbuf **mbufs,
							  uint16_t nb,
							  uint64_t ts_ns)
{
	if (hw_ts_capable_)
	{
		// 硬件时间戳：NIC已写入 mbuf->timestamp（纳秒）
		// 只需确认 ol_flags 标志，无效时用TSC兜底
		for (uint16_t i = 0; i < nb; ++i)
		{
			if (unlikely(!(mbufs[i]->ol_flags &
						   RTE_MBUF_F_RX_TIMESTAMP)))
			{
				// 硬件时间戳缺失（极少发生），用TSC兜底
				mbufs[i]->timestamp = ts_ns;
			}
			// 否则 mbuf->timestamp 已由NIC填好，不覆盖
		}
	}
	else
	{
		// TSC时间戳：整批使用同一时间点
		for (uint16_t i = 0; i < nb; ++i)
		{
			mbufs[i]->timestamp = ts_ns;
		}
	}
}

// ─────────────────────────────────────────────────────────
// 主循环
// ─────────────────────────────────────────────────────────
void RxThread::run()
{
	state_.store(ThreadState::RUNNING, std::memory_order_relaxed);
	spdlog::info("[RxThread] started: port={} queue={} lcore={} "
				 "hw_ts={} burst={}",
				 cfg_.port_id, cfg_.queue_id, cfg_.lcore_id,
				 hw_ts_capable_ ? "YES" : "NO",
				 cfg_.burst_size);

	// ── 初始化TSC换算参数 ─────────────────────────────────
	initTscConvert();

	// ── mbuf数组（栈上分配，避免heap分配）────────────────
	struct rte_mbuf *mbufs[BURST_SIZE];
	static_assert(BURST_SIZE <= 64,
				  "BURST_SIZE too large for stack allocation");

	// ── 空转计数器（自适应休眠）──────────────────────────
	uint32_t idle_count = 0;

	// ── 统计用临时变量（批量累加，减少原子操作次数）──────
	uint64_t stat_rx_pkts = 0;
	uint64_t stat_rx_bytes = 0;
	uint64_t stat_drop = 0;
	static constexpr uint32_t STAT_FLUSH_INTERVAL = 1024;
	uint32_t stat_flush_cnt = 0;

	while (likely(running_.load(std::memory_order_relaxed)))
	{

		// ══════════════════════════════════════════════════
		// 1. 批量收包
		// ══════════════════════════════════════════════════
		uint16_t nb_rx = rte_eth_rx_burst(
			cfg_.port_id,
			cfg_.queue_id,
			mbufs,
			cfg_.burst_size);

		if (unlikely(nb_rx == 0))
		{
			// ── 自适应空转休眠 ────────────────────────────
			++idle_count;
			if (idle_count < cfg_.idle_pause_thresh)
			{
				rte_pause(); // CPU暂停指令（几十ns）
			}
			else if (idle_count < cfg_.idle_sleep_thresh)
			{
				rte_delay_us_block(1); // 1μs
			}
			else
			{
				usleep(cfg_.idle_sleep_us); // 深度空闲
			}
			continue;
		}

		// 有包到达，重置空转计数
		idle_count = 0;

		// ══════════════════════════════════════════════════
		// 2. 填写时间戳
		//    在预取之前填写，让后续访问 mbuf->timestamp 命中缓存
		// ══════════════════════════════════════════════════
		uint64_t ts_ns = 0;
		if (!hw_ts_capable_)
		{
			// TSC → ns（整批共用同一时间戳）
			ts_ns = tscToNs(rte_rdtsc());
		}
		fillTimestamps(mbufs, nb_rx, ts_ns);

		// ══════════════════════════════════════════════════
		// 3. 预取包数据（流水线优化）
		//    预取第 i+4 个包，当处理第 i 个包时数据已在L1缓存
		// ══════════════════════════════════════════════════
		for (uint16_t i = 0;
			 i < std::min(nb_rx, (uint16_t)4); ++i)
		{
			rte_prefetch0(
				rte_pktmbuf_mtod(mbufs[i], void *));
		}

		// ══════════════════════════════════════════════════
		// 4. 统计更新（本地累加，延迟写入原子变量）
		// ══════════════════════════════════════════════════
		stat_rx_pkts += nb_rx;
		for (uint16_t i = 0; i < nb_rx; ++i)
		{
			stat_rx_bytes += rte_pktmbuf_pkt_len(mbufs[i]);
		}

		// ══════════════════════════════════════════════════
		// 5. 分发到各协议环（FlowDispatcher 处理）
		//
		//    FlowDispatcher 内部：
		//      - 解析以太头 EtherType / IP头 协议字段
		//      - Radius(UDP 1812/1813) → radius_ring
		//      - PPPoE(0x8863/0x8864)  → pppoe_ring
		//      - 其他                  → worker_rings[RSS哈希取模]
		//      - 无法分发的包：rte_pktmbuf_free（内部处理）
		//
		//    返回值：被丢弃的包数（环满或解析失败）
		// ══════════════════════════════════════════════════
		uint16_t nb_drop =
			cfg_.dispatcher->dispatchBurst(mbufs, nb_rx);

		stat_drop += nb_drop;

		// ══════════════════════════════════════════════════
		// 6. 定期将本地统计写入原子变量（避免每包写一次）
		// ══════════════════════════════════════════════════
		if (unlikely(++stat_flush_cnt >= STAT_FLUSH_INTERVAL))
		{
			stats_.rx_pkts.fetch_add(stat_rx_pkts,
									 std::memory_order_relaxed);
			stats_.rx_bytes.fetch_add(stat_rx_bytes,
									  std::memory_order_relaxed);
			stats_.drop_pkts.fetch_add(stat_drop,
									   std::memory_order_relaxed);
			stat_rx_pkts = 0;
			stat_rx_bytes = 0;
			stat_drop = 0;
			stat_flush_cnt = 0;
		}
	}

	// ── 退出前：将剩余统计写入 ───────────────────────────
	if (stat_rx_pkts > 0)
	{
		stats_.rx_pkts.fetch_add(stat_rx_pkts,
								 std::memory_order_relaxed);
		stats_.rx_bytes.fetch_add(stat_rx_bytes,
								  std::memory_order_relaxed);
		stats_.drop_pkts.fetch_add(stat_drop,
								   std::memory_order_relaxed);
	}

	state_.store(ThreadState::STOPPED, std::memory_order_relaxed);
	spdlog::info("[RxThread] stopped: port={} queue={} "
				 "total_rx={} total_drop={}",
				 cfg_.port_id, cfg_.queue_id,
				 stats_.rx_pkts.load(),
				 stats_.drop_pkts.load());
}