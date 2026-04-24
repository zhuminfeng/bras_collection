#pragma once
#include <cstdint>
#include <atomic>
#include <string>
#include <vector>

// ─────────────────────────────────────────────
// 每个线程的运行时统计（原子操作，跨线程读取）
// ─────────────────────────────────────────────
struct ThreadStats
{
	std::atomic<uint64_t> rx_pkts{0};
	std::atomic<uint64_t> rx_bytes{0};
	std::atomic<uint64_t> drop_pkts{0};
	std::atomic<uint64_t> radius_pkts{0};
	std::atomic<uint64_t> pppoe_pkts{0};
	std::atomic<uint64_t> user_pkts{0};
	std::atomic<uint64_t> tcp_sessions{0};
	std::atomic<uint64_t> udp_sessions{0};
	std::atomic<uint64_t> http_records{0};
	std::atomic<uint64_t> dns_records{0};
	std::atomic<uint64_t> output_records{0};
	std::atomic<uint64_t> output_bytes{0};

	// 快照（用于计算速率，Monitor线程读取）
	struct Snapshot
	{
		uint64_t rx_pkts;
		uint64_t rx_bytes;
		uint64_t drop_pkts;
		uint64_t output_records;
		double rx_pps;	  // 包/秒
		double rx_bps;	  // bits/秒
		double drop_rate; // 丢包率%
	};

	Snapshot snap_prev{};

	void reset()
	{
		rx_pkts.store(0);
		rx_bytes.store(0);
		drop_pkts.store(0);
		output_records.store(0);
	}
};

// ─────────────────────────────────────────────
// 全局统计聚合（Monitor线程写，任意线程读）
// ─────────────────────────────────────────────
class GlobalStats
{
public:
	static GlobalStats &instance()
	{
		static GlobalStats inst;
		return inst;
	}

	// 注册线程统计（启动时调用）
	void registerThread(const std::string &name, ThreadStats *st);

	// 计算并打印统计（Monitor线程每10s调用）
	void printReport(uint32_t interval_sec);

	// 获取总丢包率（给Monitor判断告警）
	double totalDropRate() const;

	// 是否超过告警阈值
	bool isDropRateAlert(double threshold_pct = 1.0) const
	{
		return totalDropRate() > threshold_pct;
	}

private:
	GlobalStats() = default;
	struct Entry
	{
		std::string name;
		ThreadStats *stats;
	};
	std::vector<Entry> entries_;
	mutable std::atomic<double> cached_drop_rate_{0.0};
};