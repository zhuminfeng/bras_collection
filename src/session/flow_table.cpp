#include "flow_table.h"

#include <stdexcept>
#include <cstring>
#include <cstdio>
#include <algorithm>

#include <spdlog/spdlog.h>
#include <arpa/inet.h>

// ─────────────────────────────────────────────────────────
// FlowKey::toString（调试用）
// ─────────────────────────────────────────────────────────
const char *FlowKey::toString() const
{
	static thread_local char buf[128];
	char user_ip_str[16], srv_ip_str[16];

	struct in_addr ua{.s_addr = htonl(user_ip)};
	struct in_addr sa{.s_addr = htonl(server_ip)};
	inet_ntop(AF_INET, &ua, user_ip_str, sizeof(user_ip_str));
	inet_ntop(AF_INET, &sa, srv_ip_str, sizeof(srv_ip_str));

	const char *proto_str =
		(proto == PROTO_TCP) ? "TCP" : (proto == PROTO_UDP) ? "UDP"
								   : (proto == PROTO_ICMP)	? "ICMP"
															: "???";

	snprintf(buf, sizeof(buf), "%s:%u → %s:%u [%s]",
			 user_ip_str, user_port,
			 srv_ip_str, server_port,
			 proto_str);
	return buf;
}

// ─────────────────────────────────────────────────────────
// 构造
// ─────────────────────────────────────────────────────────
FlowTable::FlowTable(uint32_t capacity,
					 uint64_t tcp_timeout_us,
					 uint64_t udp_timeout_us,
					 uint64_t icmp_timeout_us)
	: tcp_timeout_us_(tcp_timeout_us),
	  udp_timeout_us_(udp_timeout_us),
	  icmp_timeout_us_(icmp_timeout_us)
{
	// 向上对齐到2的幂
	uint32_t p = 1;
	while (p < capacity)
		p <<= 1;
	cap_ = p;
	mask_ = p - 1;

	// 预分配，全部置零初始化
	table_.resize(cap_);

	spdlog::info("[FlowTable] created: capacity={} "
				 "tcp_timeout={}s udp_timeout={}s icmp_timeout={}s",
				 cap_,
				 tcp_timeout_us / 1000000,
				 udp_timeout_us / 1000000,
				 icmp_timeout_us / 1000000);
}

// ─────────────────────────────────────────────────────────
// 析构：释放所有 nDPI 状态内存
// ─────────────────────────────────────────────────────────
FlowTable::~FlowTable()
{
	for (auto &fe : table_)
	{
		if (fe.in_use)
		{
			releaseNdpi(fe);
		}
	}
}

// ─────────────────────────────────────────────────────────
// 哈希函数（Murmur3 finalizer mix）
// 对5元组所有字段做混合，保证分布均匀
// ─────────────────────────────────────────────────────────
uint32_t FlowTable::hash(const FlowKey &key) const
{
	// 将5元组拼成两个64位数做混合
	uint64_t h1 = ((uint64_t)key.user_ip << 32) | key.server_ip;
	uint64_t h2 = ((uint64_t)key.user_port << 16) |
				  (uint64_t)key.server_port |
				  ((uint64_t)key.proto << 32);

	// Murmur3 mix
	auto mix64 = [](uint64_t k) -> uint64_t
	{
		k ^= k >> 33;
		k *= 0xff51afd7ed558ccdULL;
		k ^= k >> 33;
		k *= 0xc4ceb9fe1a85ec53ULL;
		k ^= k >> 33;
		return k;
	};

	uint64_t h = mix64(h1 ^ mix64(h2));
	return (uint32_t)(h & mask_);
}

// ─────────────────────────────────────────────────────────
// 内部探测函数
//
// 线性探测查找key：
//   - 遇到空槽（!in_use && !is_tombstone）：key不存在
//   - 遇到墓碑：继续探测，但记录第一个墓碑位置
//   - 遇到匹配key：命中
//
// found=true：返回命中槽的索引
// found=false：返回可插入槽的索引（空槽或第一个墓碑）
// 返�� UINT32_MAX：表满，无法插入
// ─────────────────────────────────────────────────────────
uint32_t FlowTable::probe(const FlowKey &key,
						  bool *found,
						  uint32_t *insert_slot) const
{
	*found = false;
	uint32_t start = hash(key);
	uint32_t first_tomb = UINT32_MAX; // 第一个墓碑槽位置

	for (uint32_t i = 0; i < MAX_PROBE_DEPTH; ++i)
	{
		uint32_t idx = (start + i) & mask_;
		const FlowEntry &fe = table_[idx];

		if (fe.is_tombstone)
		{
			// 墓碑：记录第一个，继续探测
			if (first_tomb == UINT32_MAX)
				first_tomb = idx;
			continue;
		}

		if (!fe.in_use)
		{
			// 空槽：key不存在
			// 插入优先用墓碑槽（减少碎片）
			if (insert_slot)
			{
				*insert_slot = (first_tomb != UINT32_MAX)
								   ? first_tomb
								   : idx;
			}
			return idx; // 返回空槽位置（未命中）
		}

		if (fe.key == key)
		{
			// 命中
			*found = true;
			if (insert_slot)
				*insert_slot = idx;
			return idx;
		}

		// 占用但不匹配：冲突，继续探测
		++const_cast<FlowTable *>(this)->stat_collisions_;
	}

	// 超过最大探测深度
	// 优先返回墓碑槽（复用），否则表满
	if (insert_slot)
	{
		*insert_slot = (first_tomb != UINT32_MAX)
						   ? first_tomb
						   : UINT32_MAX;
	}
	return UINT32_MAX;
}

// ─────────────────────────────────────────────────────────
// getOrCreate：查找或新建流
// ─────────────────────────────────────────────────────────
FlowEntry *FlowTable::getOrCreate(const FlowKey &key,
								  uint64_t now_us,
								  bool *created)
{
	if (created)
		*created = false;

	bool found = false;
	uint32_t insert_slot = UINT32_MAX;
	uint32_t idx = probe(key, &found, &insert_slot);

	// ── 命中已有流 ────────────────────────────────────────
	if (found)
	{
		FlowEntry &fe = table_[idx];
		fe.last_us = now_us;
		return &fe;
	}

	// ── 表满检查 ──────────────────────────────────────────
	if (insert_slot == UINT32_MAX)
	{
		spdlog::warn("[FlowTable] table full! "
					 "used={} cap={} load={:.1f}% key={}",
					 used_, cap_, loadFactor() * 100.0f,
					 key.toString());
		return nullptr;
	}

	// ── 负载因子过高：提前告警 ────────────────────────────
	if (loadFactor() > 0.85f)
	{
		spdlog::warn("[FlowTable] load factor {:.1f}% > 85%, "
					 "consider increasing capacity",
					 loadFactor() * 100.0f);
	}

	// ── 创建新流 ──────────────────────────────────────────
	FlowEntry &fe = table_[insert_slot];

	// 如果复用墓碑槽，先完全reset
	if (fe.is_tombstone)
	{
		fe.reset();
		--tombstone_count_;
	}

	fe.in_use = true;
	fe.key = key;
	fe.proto = key.proto;
	fe.create_us = now_us;
	fe.last_us = now_us;
	fe.probe_count = (uint16_t)(insert_slot != hash(key)
									? (insert_slot - hash(key) + cap_) & mask_
									: 0);

	// 初始化HTTP端口判断
	fe.is_http = (key.proto == PROTO_TCP) &&
				 (key.server_port == 80 ||
				  key.server_port == 8080 ||
				  key.server_port == 8000 ||
				  key.server_port == 8888 ||
				  key.server_port == 3128);

	// 初始化nDPI流状态
	initNdpi(fe);

	++used_;
	++stat_created_;

	if (created)
		*created = true;

	return &fe;
}

// ─────────────────────────────────────────────────────────
// find：仅查找
// ─────────────────────────────────────────────────────────
FlowEntry *FlowTable::find(const FlowKey &key)
{
	bool found = false;
	uint32_t idx = probe(key, &found, nullptr);
	if (!found)
		return nullptr;
	return &table_[idx];
}

// ────────────────────���────────────────────────────────────
// remove：主动删除（TCP RST/FIN后调用）
// 使用墓碑标记，避免破坏探测链
// ─────────────────────────────────────────────────────────
bool FlowTable::remove(const FlowKey &key,
					   std::function<void(FlowEntry &)> on_remove)
{
	bool found = false;
	uint32_t idx = probe(key, &found, nullptr);
	if (!found)
		return false;

	FlowEntry &fe = table_[idx];

	// 先回调（输出记录）
	if (on_remove)
		on_remove(fe);

	// 释放nDPI内存
	releaseNdpi(fe);

	// 标记为墓碑（不立即reset，保护探测链）
	fe.in_use = false;
	fe.is_tombstone = true;
	fe.key = FlowKey{}; // 清除key防止误命中

	--used_;
	++tombstone_count_;
	++stat_removed_;

	// 墓碑比例过高时触发rehash
	if ((float)tombstone_count_ / (float)cap_ >= TOMBSTONE_RATIO_THRESHOLD)
	{
		spdlog::debug("[FlowTable] tombstone ratio {:.1f}% >= {:.0f}%, "
					  "triggering rehash",
					  (float)tombstone_count_ / (float)cap_ * 100.0f,
					  TOMBSTONE_RATIO_THRESHOLD * 100.0f);
		rehash();
	}

	return true;
}

// ─────────────────────────────────────────────────────────
// purgeExpired：清理超时流
// 遍历全表，对超时流调用回调后reset
// ─────────────────────────────────────────────────────────
uint32_t FlowTable::purgeExpired(uint64_t now_us,
								 std::function<void(FlowEntry &)> on_expire)
{
	uint32_t purged = 0;

	for (uint32_t i = 0; i < cap_; ++i)
	{
		FlowEntry &fe = table_[i];

		// 跳过空槽和墓碑
		if (!fe.in_use || fe.is_tombstone)
			continue;

		// 判断是否超时（按协议选择超时时间）
		uint64_t timeout = getTimeout(fe.proto);
		if (!fe.isExpired(now_us, timeout))
			continue;

		// 回调（输出记录）
		if (on_expire)
			on_expire(fe);

		// 释放nDPI内存
		releaseNdpi(fe);

		// 标记墓碑
		fe.in_use = false;
		fe.is_tombstone = true;
		fe.key = FlowKey{};

		--used_;
		++tombstone_count_;
		++stat_expired_;
		++purged;
	}

	// purge后检查是否需要rehash
	if ((float)tombstone_count_ / (float)cap_ >= TOMBSTONE_RATIO_THRESHOLD)
	{
		rehash();
	}

	if (purged > 0)
	{
		spdlog::debug("[FlowTable] purged {} expired flows, "
					  "remaining={} tombstones={}",
					  purged, used_, tombstone_count_);
	}

	return purged;
}

// ─────────────────────────────────────────────────────────
// purgeAll：清理所有流（程序退出时调用）
// ─────────────────────────────────────────────────────────
uint32_t FlowTable::purgeAll(std::function<void(FlowEntry &)> on_expire)
{
	uint32_t purged = 0;

	for (uint32_t i = 0; i < cap_; ++i)
	{
		FlowEntry &fe = table_[i];
		if (!fe.in_use || fe.is_tombstone)
			continue;

		if (on_expire)
			on_expire(fe);
		releaseNdpi(fe);

		fe.reset();
		++purged;
	}

	used_ = 0;
	tombstone_count_ = 0;

	spdlog::info("[FlowTable] purgeAll: flushed {} flows", purged);
	return purged;
}

// ─────────────────────────────────────────────────────────
// rehash：重建哈希表，消除墓碑碎片
//
// 步骤：
//   1. 将所有活跃流复制到临时vector
//   2. 清空table_
//   3. 重新插入所有流
// ─────────────────────────────────────────────────────────
void FlowTable::rehash()
{
	spdlog::info("[FlowTable] rehash start: used={} tombstones={}",
				 used_, tombstone_count_);

	// 收集所有活跃流
	std::vector<FlowEntry> live;
	live.reserve(used_);

	for (auto &fe : table_)
	{
		if (fe.in_use && !fe.is_tombstone)
		{
			live.push_back(fe);
		}
	}

	// 清空表
	for (auto &fe : table_)
	{
		// 注意：nDPI内存已在live中持有，不能释放
		fe.in_use = false;
		fe.is_tombstone = false;
		fe.key = FlowKey{};
	}
	used_ = 0;
	tombstone_count_ = 0;

	// 重新插入
	for (auto &src : live)
	{
		bool found_dummy = false;
		uint32_t insert_slot = UINT32_MAX;
		probe(src.key, &found_dummy, &insert_slot);

		if (insert_slot == UINT32_MAX)
		{
			// 理论上不会发生（表没变大小，live元素数≤used_）
			spdlog::error("[FlowTable] rehash: insert failed for {}",
						  src.key.toString());
			// 释放该流的nDPI内存
			releaseNdpi(const_cast<FlowEntry &>(src));
			continue;
		}

		table_[insert_slot] = src;
		++used_;
	}

	spdlog::info("[FlowTable] rehash done: used={} tombstones=0", used_);
}

// ─────────────────────────────────────────────────────────
// nDPI流状态初始化
// 为每个新流分配 ndpi_flow_struct / ndpi_id_struct
// ─────────────────────────────────────────────────────────
void FlowTable::initNdpi(FlowEntry &fe)
{
	// ndpi_flow_struct 和 ndpi_id_struct 需要 calloc 分配
	// （nDPI��部会做指针算术，必须是连续内存）
	fe.ndpi_state.ndpi_flow = (ndpi_flow_struct *)
		calloc(1, ndpi_flow_struct_size());
	fe.ndpi_state.src_id = (ndpi_id_struct *)
		calloc(1, ndpi_sizeof_id_struct());
	fe.ndpi_state.dst_id = (ndpi_id_struct *)
		calloc(1, ndpi_sizeof_id_struct());
	fe.ndpi_state.pkt_count = 0;
	fe.ndpi_state.detection_done = false;
	fe.ndpi_state.detected_proto = {};
}

// ─────────────────────────────────────────────────────────
// nDPI流状态释放
// ─────────────────────────────────────────────────────────
void FlowTable::releaseNdpi(FlowEntry &fe)
{
	if (fe.ndpi_state.ndpi_flow)
	{
		ndpi_free_flow(fe.ndpi_state.ndpi_flow);
		fe.ndpi_state.ndpi_flow = nullptr;
	}
	if (fe.ndpi_state.src_id)
	{
		free(fe.ndpi_state.src_id);
		fe.ndpi_state.src_id = nullptr;
	}
	if (fe.ndpi_state.dst_id)
	{
		free(fe.ndpi_state.dst_id);
		fe.ndpi_state.dst_id = nullptr;
	}
}