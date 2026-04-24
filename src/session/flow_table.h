#pragma once

#include <cstdint>
#include <cstring>
#include <functional>
#include <vector>

#include "tcp_session.h"
#include "http_session.h"
#include "udp_session.h"
#include "../parser/ndpi_analyzer.h"
#include "../../include/common.h"

// ─────────────────────────────────────────────────────────
// 五元组 Key（方向归一化：user侧始终为src）
// ─────────────────────────────────────────────────────────
struct FlowKey
{
	uint32_t user_ip = 0;
	uint32_t server_ip = 0;
	uint16_t user_port = 0;
	uint16_t server_port = 0;
	uint8_t proto = 0; // IPPROTO_TCP / UDP / ICMP

	bool operator==(const FlowKey &o) const
	{
		// 用单次memcmp比多次字段比较更快（CPU可并行）
		return memcmp(this, &o, sizeof(FlowKey)) == 0;
	}

	bool operator!=(const FlowKey &o) const
	{
		return !(*this == o);
	}

	bool empty() const
	{
		return user_ip == 0 && server_ip == 0;
	}

	// 调试用：转字符串
	// 注意：返回static缓冲区，非线程安全，仅用于日志
	const char *toString() const;
};

// ─────────────────────────────────────────────────────────
// ICMP会话状态（轻量，不需要 tcp_session.h 的复杂状态机）
// ─────────────────────────────────────────────────────────
struct IcmpSession
{
	uint64_t create_us = 0;
	uint64_t last_us = 0;
	uint32_t req_count = 0; // 请求包数（Echo Request）
	uint32_t rsp_count = 0; // 响应包数（Echo Reply）
	uint32_t rtt_sum_ms = 0;
	uint32_t rtt_count = 0;
	uint16_t last_seq = 0;
	uint64_t last_req_ts_us = 0; // 上一个请求包时间
	uint32_t payload_size = 0;	 // ICMP payload大小
	uint32_t total_duration_ms = 0;
};

// ─────────────────────────────────────────────────────────
// FlowEntry：一条完整的网络流
//
// 内存布局设计原则：
//   - 热数据（key/时间/标志）放前面，利用缓存行
//   - 冷数据（HTTP头缓冲/nDPI结构）放后面
//   - 整体对齐到64字节缓存行边界
// ─────────────────────────────────────────────────────────
struct alignas(64) FlowEntry
{

	// ══ 热数据区（前64字节，第一个缓存行）══════════════════
	FlowKey key{}; // 20字节
	bool in_use = false;
	uint8_t proto = 0; // 冗余存储，避免每次从key取
	uint8_t _pad[2] = {};

	uint64_t create_us = 0; // 流创建时间（微秒）
	uint64_t last_us = 0;	// 最后收包时间（微秒）

	// ══ 用户信息区 ══════════════════════════════════════════
	uint64_t user_mac = 0; // 用户侧MAC（uint64）
	uint64_t bras_mac = 0; // BRAS MAC
	char user_account[256] = {};
	bool account_filled = false;

	// ══ 协议标志区 ══════════════════════════════════════════
	bool is_http = false;		 // 是否走HTTP解析
	bool is_rtp = false;		 // 是否为RTP流（视频/语音）
	uint8_t traffic_type = 0;	 // nDPI业务分类
	uint32_t ndpi_app_proto = 0; // nDPI应用协议ID
	char ndpi_app_name[32] = {};

	// ══ 各协议会话数据区 ════════════════════════════════════
	TcpSession tcp{};	// TCP状态机 + RTT + 丢包
	HttpSession http{}; // HTTP头解析（仅is_http时有效）
	UdpSession udp{};	// UDP流统计
	IcmpSession icmp{}; // ICMP Ping统计

	// ══ nDPI流状态（DPI检测）════════════════════════════════
	NdpiFlowState ndpi_state{};

	// ══ 哈希冲突链（开放地址法辅助）════════════════════════
	// probe_count：当前entry经过了多少次线性探测才落在此槽
	// 用于删除时的墓碑标记判断
	uint16_t probe_count = 0;
	bool is_tombstone = false; // 墓碑标记（逻辑删除）

	// ── 方法 ─────────────────────────────────────────────

	// 重置为空闲状态（不释放内存，复用槽位）
	void reset()
	{
		in_use = false;
		is_tombstone = false;
		probe_count = 0;
		proto = 0;
		create_us = 0;
		last_us = 0;
		user_mac = 0;
		bras_mac = 0;
		user_account[0] = '\0';
		account_filled = false;
		is_http = false;
		is_rtp = false;
		traffic_type = 0;
		ndpi_app_proto = 0;
		ndpi_app_name[0] = '\0';
		key = FlowKey{};
		tcp = TcpSession{};
		http = HttpSession{};
		udp = UdpSession{};
		icmp = IcmpSession{};
		// nDPI状态由FlowTable::releaseNdpi()单独处理
	}

	// 流是否超时
	bool isExpired(uint64_t now_us, uint64_t timeout_us) const
	{
		return in_use && (now_us - last_us) >= timeout_us;
	}

	// 流时长（微秒）
	uint64_t durationUs() const
	{
		return (last_us >= create_us) ? (last_us - create_us) : 0;
	}
};

// ─────────────────────────────────────────────────────────
// FlowTable
//
// 实现：开放地址哈希表（线性探测）
//   - 单线程使用（每个Worker独占一个实例）
//   - 无锁，无内存分配（预分配固定大小）
//   - 支持墓碑删除，避免破坏探测链
//   - 容量必须是2的幂
//
// 容量建议：
//   - 100G场景：同时活跃流约500K~1M
//   - 建议容量 = 预期最大流数 * 1.5（降低碰撞概率）
//   - 示例：1M流 → capacity = 1<<21 = 2M槽
//
// 超时策略：
//   - TCP已关闭流：立即输出，reset槽位
//   - TCP超时流（无FIN/RST）：120s
//   - UDP流：60s
//   - ICMP流：30s
// ─────────────────────────────────────────────────────────
class FlowTable
{
public:
	// timeout_us：流超时时间（微秒）
	explicit FlowTable(uint32_t capacity,
					   uint64_t tcp_timeout_us = 120ULL * 1000000,
					   uint64_t udp_timeout_us = 60ULL * 1000000,
					   uint64_t icmp_timeout_us = 30ULL * 1000000);
	~FlowTable();

	// ── 核心操作 ─────────────────────────────────────────

	// 查找或创建流条目
	// now_us：当前时间（微秒）
	// created：出参，true表示新建了流
	// 返回nullptr表示表满（极端情况）
	FlowEntry *getOrCreate(const FlowKey &key,
						   uint64_t now_us,
						   bool *created = nullptr);

	// 仅查找，不创建
	// 返回nullptr表示不存在
	FlowEntry *find(const FlowKey &key);

	// 主动删除（RST/FIN后调用，先回调输出再reset）
	// 返回true表示找到并删除
	bool remove(const FlowKey &key,
				std::function<void(FlowEntry &)> on_remove = nullptr);

	// ── 定期清理 ─────────────────────────────────────────

	// 清理超时流
	// now_us：当前时间
	// on_expire：每条超时���的回调（用于输出记录）
	// 返回：本次清理的流数量
	uint32_t purgeExpired(uint64_t now_us,
						  std::function<void(FlowEntry &)> on_expire);

	// 清理所有流（程序退出时调用）
	uint32_t purgeAll(std::function<void(FlowEntry &)> on_expire);

	// ── 统计 ─────────────────────────────────────────────
	uint32_t size() const { return used_; }
	uint32_t capacity() const { return cap_; }
	uint32_t tombstones() const { return tombstone_count_; }

	// 负载因子（used / capacity）
	float loadFactor() const
	{
		return cap_ > 0 ? (float)used_ / (float)cap_ : 0.0f;
	}

	// 累计统计
	uint64_t totalCreated() const { return stat_created_; }
	uint64_t totalExpired() const { return stat_expired_; }
	uint64_t totalRemoved() const { return stat_removed_; }
	uint64_t totalCollisions() const { return stat_collisions_; }

	// ── 维护 ─────────────────────────────────────────────

	// 重建哈希表（清除墓碑，整理碎片）
	// 建议墓碑数 > capacity/4 时调用
	void rehash();

	// 禁止拷贝
	FlowTable(const FlowTable &) = delete;
	FlowTable &operator=(const FlowTable &) = delete;

private:
	// ── 哈希函数 ────────────────────────────────────────���
	// 使用 Murmur3 mix，比简单乘法哈希碰撞率更低
	uint32_t hash(const FlowKey &key) const;

	// ── 内部查找（返回槽位索引）─────────────────────────
	// 查找key对应的槽位：
	//   - 存在：返回其索引
	//   - 不存在：返回第一个空槽或墓碑槽的索引（用于插入）
	//   - 表满：返回UINT32_MAX
	uint32_t probe(const FlowKey &key,
				   bool *found,
				   uint32_t *insert_slot = nullptr) const;

	// ── nDPI流状态管理 ───────────────────────────────────
	// 为新流初始化nDPI状态
	void initNdpi(FlowEntry &fe);
	// 释放nDPI状态内存
	void releaseNdpi(FlowEntry &fe);

	// ── 根据协议选择超时时间 ─────────────────────────────
	uint64_t getTimeout(uint8_t proto) const
	{
		switch (proto)
		{
		case PROTO_TCP:
			return tcp_timeout_us_;
		case PROTO_UDP:
			return udp_timeout_us_;
		case PROTO_ICMP:
			return icmp_timeout_us_;
		default:
			return tcp_timeout_us_;
		}
	}

	// ── 数据成员 ─────────────────────────────────────────
	std::vector<FlowEntry> table_; // 预分配的哈希槽数组
	uint32_t cap_;				   // 容量（2的幂）
	uint32_t mask_;				   // cap_ - 1（位掩码）
	uint32_t used_ = 0;			   // 当前活跃流数
	uint32_t tombstone_count_ = 0; // 墓碑数量

	uint64_t tcp_timeout_us_;
	uint64_t udp_timeout_us_;
	uint64_t icmp_timeout_us_;

	// 累计统计（无需原子，单线程访问）
	uint64_t stat_created_ = 0;
	uint64_t stat_expired_ = 0;
	uint64_t stat_removed_ = 0;
	uint64_t stat_collisions_ = 0;

	// 上次rehash时间（us）
	uint64_t last_rehash_us_ = 0;

	// 最大探测深度（超过此值说明哈希表过满）
	static constexpr uint32_t MAX_PROBE_DEPTH = 32;

	// 自动rehash触发阈值
	static constexpr float TOMBSTONE_RATIO_THRESHOLD = 0.25f;
};