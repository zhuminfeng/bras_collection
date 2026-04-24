#include "flow_dispatcher.h"

#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_ether.h>
#include <rte_byteorder.h>
#include <rte_prefetch.h>

#include <algorithm>
#include <cstring>
#include <spdlog/spdlog.h>

// ─────────────────────────────────────────────────────────
// 构造
// ─────────────────────────────────────────────────────────
FlowDispatcher::FlowDispatcher(const DispatchConfig &cfg)
	: cfg_(cfg)
{
}

// ─────────────────────────────────────────────────────────
// 核心分发
// ─────────────────────────────────────────────────────────
uint16_t FlowDispatcher::dispatchBurst(struct rte_mbuf **mbufs,
									   uint16_t nb)
{
	// ── 分桶缓冲（避免逐包enqueue，改为批量enqueue）──────
	// radius / pppoe 量少，直接逐包enqueue
	// worker 按队列分组批量enqueue
	static thread_local struct rte_mbuf *
		worker_batch[MAX_WORKERS][BURST_SIZE];
	static thread_local uint16_t worker_cnt[MAX_WORKERS];

	// 初始化worker分桶计数
	const uint16_t nb_workers =
		(uint16_t)worker_rings_.size();
	memset(worker_cnt, 0, sizeof(uint16_t) * nb_workers);

	uint16_t nb_drop = 0;

	for (uint16_t i = 0; i < nb; ++i)
	{
		// 预取下一个包（流水线优化）
		if (i + 4 < nb)
			rte_prefetch0(
				rte_pktmbuf_mtod(mbufs[i + 4], void *));

		struct rte_mbuf *m = mbufs[i];
		PktType type = classify(m);

		switch (type)
		{

		// ── Radius ────────────────────────────────────────
		case PKT_RADIUS:
			if (likely(radius_ring_))
			{
				if (unlikely(rte_ring_enqueue(
								 radius_ring_, m) != 0))
				{
					// Radius环满（极少发生）
					rte_pktmbuf_free(m);
					++nb_drop;
					spdlog::warn("[Dispatcher] radius_ring full, "
								 "dropped 1 pkt");
				}
				else
				{
					stat_radius_.fetch_add(
						1, std::memory_order_relaxed);
				}
			}
			else
			{
				// 没有配置Radius环，降级为用户流量
				goto dispatch_user;
			}
			break;

		// ── PPPoE ─────────────────────────────────────────
		case PKT_PPPOE:
			if (likely(pppoe_ring_))
			{
				if (unlikely(rte_ring_enqueue(
								 pppoe_ring_, m) != 0))
				{
					rte_pktmbuf_free(m);
					++nb_drop;
				}
				else
				{
					stat_pppoe_.fetch_add(
						1, std::memory_order_relaxed);
				}
			}
			else
			{
				goto dispatch_user;
			}
			break;

		// ── 用户流量 → Worker ─────────────────────────────
		case PKT_USER:
		dispatch_user:
			if (likely(nb_workers > 0))
			{
				uint16_t wid = selectWorker(m);
				worker_batch[wid][worker_cnt[wid]++] = m;
				stat_user_.fetch_add(
					1, std::memory_order_relaxed);
			}
			else
			{
				rte_pktmbuf_free(m);
				++nb_drop;
			}
			break;

		// ── 无效包 ────────────────────────────────────────
		default:
			rte_pktmbuf_free(m);
			++nb_drop;
			break;
		}
	}

	// ── 批量 enqueue 到 worker rings ──────────────────────
	for (uint16_t w = 0; w < nb_workers; ++w)
	{
		if (worker_cnt[w] == 0)
			continue;

		uint16_t enqueued = (uint16_t)
			rte_ring_enqueue_burst(
				worker_rings_[w],
				(void **)worker_batch[w],
				worker_cnt[w],
				nullptr);

		// enqueue 失败的包（ring满）需要 free
		if (unlikely(enqueued < worker_cnt[w]))
		{
			uint16_t dropped = worker_cnt[w] - enqueued;
			for (uint16_t j = enqueued;
				 j < worker_cnt[w]; ++j)
			{
				rte_pktmbuf_free(worker_batch[w][j]);
			}
			nb_drop += dropped;
			stat_drop_.fetch_add(
				dropped, std::memory_order_relaxed);

			// 反压日志（限频：避免日志淹没）
			static thread_local uint64_t last_warn_tsc = 0;
			uint64_t now = rte_rdtsc();
			if (now - last_warn_tsc > rte_get_tsc_hz())
			{
				spdlog::warn(
					"[Dispatcher] worker_ring[{}] full, "
					"dropped {} pkts",
					w, dropped);
				last_warn_tsc = now;
			}
		}
	}

	if (unlikely(nb_drop > 0))
	{
		stat_drop_.fetch_add(nb_drop,
							 std::memory_order_relaxed);
	}

	return nb_drop;
}

// ─────────────────────────────────────────────────────────
// 包分类
//
// 分类优先级：
//   1. EtherType == 0x8863/0x8864 → PPPoE
//   2. UDP dst/src == 1812/1813
//      且 IP 为 Radius 服务器     → Radius
//   3. 其他                        → User
//   4. 解析失败                    → Invalid
// ─────────────────────────────────────────────────────────
PktType FlowDispatcher::classify(struct rte_mbuf *mbuf) const
{
	const uint8_t *data = rte_pktmbuf_mtod(mbuf, const uint8_t *);
	uint32_t pkt_len = rte_pktmbuf_pkt_len(mbuf);

	// ── 最小包长检查（以太头14字节）─────────────────────
	if (unlikely(pkt_len < sizeof(rte_ether_hdr)))
		return PKT_INVALID;

	const auto *eth =
		reinterpret_cast<const rte_ether_hdr *>(data);
	uint16_t etype =
		rte_be_to_cpu_16(eth->ether_type);
	uint32_t offset = sizeof(rte_ether_hdr);

	// ── PPPoE Discovery（0x8863）────────────────────────
	if (etype == 0x8863)
		return PKT_PPPOE;

	// ── 剥离 VLAN（802.1Q / QinQ）────────────────────────
	while ((etype == 0x8100 || etype == 0x88A8) &&
		   offset + 4 <= pkt_len)
	{
		etype = rte_be_to_cpu_16(
			*reinterpret_cast<const uint16_t *>(
				data + offset + 2));
		offset += 4;
	}

	// ── PPPoE Session（VLAN之后可能出现）─────────────────
	if (etype == 0x8864)
		return PKT_PPPOE;

	// ── 非IPv4：直接作为用户流量（IPv6可扩展）────────────
	if (etype != 0x0800)
		return PKT_USER;

	// ── IPv4 头解析 ───────────────────────────────────────
	if (unlikely(offset + sizeof(rte_ipv4_hdr) > pkt_len))
		return PKT_INVALID;

	const auto *ip =
		reinterpret_cast<const rte_ipv4_hdr *>(data + offset);
	uint8_t ip_proto = ip->next_proto_id;
	uint32_t src_ip = rte_be_to_cpu_32(ip->src_addr);
	uint32_t dst_ip = rte_be_to_cpu_32(ip->dst_addr);
	uint32_t ip_hlen = (ip->version_ihl & 0x0F) * 4;
	offset += ip_hlen;

	// ── UDP → 检查 Radius 端口 ────────────────────────────
	if (ip_proto == IPPROTO_UDP)
	{
		if (unlikely(offset + sizeof(rte_udp_hdr) > pkt_len))
			return PKT_USER;

		const auto *udp =
			reinterpret_cast<const rte_udp_hdr *>(data + offset);
		uint16_t src_port =
			rte_be_to_cpu_16(udp->src_port);
		uint16_t dst_port =
			rte_be_to_cpu_16(udp->dst_port);

		// Radius端口：1812(Auth) / 1813(Acct) / 3799(CoA)
		bool is_radius_port =
			(dst_port == 1812 || dst_port == 1813 ||
			 dst_port == 3799 ||
			 src_port == 1812 || src_port == 1813 ||
			 src_port == 3799);

		if (is_radius_port)
		{
			// 还需确认 IP 是 Radius 服务器（防误判）
			if (isRadiusServer(src_ip) ||
				isRadiusServer(dst_ip))
			{
				return PKT_RADIUS;
			}
		}

		// DNS（UDP 53）：作为用户流量，Worker线程解析
		return PKT_USER;
	}

	return PKT_USER;
}

// ─────────────────────────────────────────────────────────
// Worker 队列选择
//
// 优先使用 NIC 硬件 RSS 哈希（ConnectX-5/i40e 已计算好）
// 没有 RSS 哈希时：提取 IP 五元组做软件哈希
// ─────────────────────────────────────────────────────────
uint16_t FlowDispatcher::selectWorker(struct rte_mbuf *mbuf) const
{
	const uint16_t nb_workers = (uint16_t)worker_rings_.size();
	if (nb_workers == 1)
		return 0;

	// ── 优先使用硬件RSS哈希（已在RxThread中由NIC计算）───
	if (mbuf->ol_flags & RTE_MBUF_F_RX_RSS_HASH)
	{
		return (uint16_t)(mbuf->hash.rss % nb_workers);
	}

	// ── 软件哈希（fallback：从IP头提取五元组）────────────
	const uint8_t *data = rte_pktmbuf_mtod(mbuf, const uint8_t *);
	uint32_t pkt_len = rte_pktmbuf_pkt_len(mbuf);

	// 跳过以太头和VLAN
	uint32_t offset = sizeof(rte_ether_hdr);
	if (pkt_len < offset + sizeof(rte_ipv4_hdr))
		return 0;

	const auto *eth =
		reinterpret_cast<const rte_ether_hdr *>(data);
	uint16_t etype = rte_be_to_cpu_16(eth->ether_type);
	while ((etype == 0x8100 || etype == 0x88A8) &&
		   offset + 4 <= pkt_len)
	{
		etype = rte_be_to_cpu_16(
			*reinterpret_cast<const uint16_t *>(
				data + offset + 2));
		offset += 4;
	}

	if (etype != 0x0800 ||
		offset + sizeof(rte_ipv4_hdr) > pkt_len)
		return 0;

	const auto *ip =
		reinterpret_cast<const rte_ipv4_hdr *>(data + offset);
	uint32_t src_ip = ip->src_addr;
	uint32_t dst_ip = ip->dst_addr;
	offset += (ip->version_ihl & 0x0F) * 4;

	uint16_t src_port = 0, dst_port = 0;
	if (offset + 4 <= pkt_len)
	{
		src_port = *reinterpret_cast<const uint16_t *>(
			data + offset);
		dst_port = *reinterpret_cast<const uint16_t *>(
			data + offset + 2);
	}

	// 对称哈希：保证同一流双向落到同一Worker
	// (src_ip ^ dst_ip) 使得交换src/dst结果不变
	uint32_t h = (src_ip ^ dst_ip);
	h ^= ((uint32_t)(src_port ^ dst_port) << 16);
	// Knuth 乘法哈希
	h = (uint32_t)(h * 2654435761UL);

	return (uint16_t)(h % nb_workers);
}

// ─────────────────────────────────────────────────────────
// 判断 IP 是否为 Radius 服务器
// ─────────────────────────────────────────────────────────
bool FlowDispatcher::isRadiusServer(uint32_t ip) const
{
	for (uint32_t srv : cfg_.radius_server_ips)
	{
		if (ip == srv)
			return true;
	}
	return false;
}