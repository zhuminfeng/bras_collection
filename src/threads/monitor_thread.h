#pragma once

#include <atomic>
#include <thread>
#include <vector>
#include <memory>
#include <cstdint>
#include <cstring>
#include <functional>

#include "../../include/common.h"
#include "../utils/stats.h"

// 前向声明（避免循环依赖）
class RxThread;
class WorkerThread;
class RadiusThread;
class OutputThread;
class FlowDispatcher;

// ─────────────────────────────────────────────────────────
// 各线程健康快照（每次检查周期保存一次）
// 用于计算速率和判断线程是否stall
// ─────────────────────────────────────────────────────────
struct ThreadHealthSnapshot
{
	uint64_t rx_pkts = 0;
	uint64_t drop_pkts = 0;
	uint64_t output_records = 0;
	uint64_t rx_bytes = 0;
	bool was_running = false;
};

// ─────────────────────────────────────────────────────────
// NIC端口瞬时统计（用于计算增量速率）
// ─────────────────────────────────────────────────────────
struct NicSnapshot
{
	uint64_t ipackets = 0;
	uint64_t opackets = 0;
	uint64_t ibytes = 0;
	uint64_t imissed = 0;
	uint64_t ierrors = 0;
};

// ─────────────────────────────────────────────────────────
// MonitorThread
//
// 职责：
//   1. 定期打印各线程统计（包速率、吞吐量、丢包率）
//   2. 打印NIC硬件统计（imissed/ierrors）
//   3. 检测Worker/Rx线程是否stall（有流量但包数不增长）
//   4. stall时尝试重启对应线程
//   5. 检测输出队列水位，告警反压
//   6. 检测系统资源（CPU/内存）
//   7. 所有告警通过spdlog输出，可接入告警系统
//
// 线程模型：
//   - 独立 std::thread，不占用 DPDK lcore
//   - 只读访问各线程的 ThreadStats（原子操作）
//   - 写操作只有：调用线程的 restart()
// ─────────────────────────────────────────────────────────
class MonitorThread : NonCopyable
{
public:
	// ── 构造参数 ─────────────────────────────────────────
	struct Config
	{
		uint32_t report_interval_sec = 10; // 统计打印间隔
		uint32_t stall_check_sec = 30;	   // stall检测间隔
		double drop_rate_warn_pct = 1.0;   // 丢包率告警阈值(%)
		double drop_rate_crit_pct = 5.0;   // 丢包率严重阈值(%)
		float queue_warn_level = 0.8f;	   // 队列水位告警(0~1)
		bool enable_restart = true;		   // stall时是否自动重启
		// NIC总流量低于此值时不做stall判断（避免无流量误判）
		uint64_t min_rx_pps_for_stall = 1000;
	};

	explicit MonitorThread(const Config &cfg);
	~MonitorThread();

	// ── 注册被监控的线程（启动前调用）──────────────────
	void registerRx(RxThread *t, uint32_t lcore_id = 0);
	void registerWorker(WorkerThread *t, uint32_t lcore_id = 0);
	void registerRadius(RadiusThread *t);
	void registerOutput(OutputThread *t);
	void setDispatcher(FlowDispatcher *d);

	// ── 生命周期 ─────────────────────────────────────────
	void start();
	void stop();
	void join();

	bool isRunning() const
	{
		return state_.load(std::memory_order_relaxed) == ThreadState::RUNNING;
	}

	// ── 外部访问（可供HTTP管理接口调用）─────────────────
	// 获取最近一次打印的系统摘要
	struct SystemSummary
	{
		double total_rx_pps;	   // 总收包速率
		double total_rx_gbps;	   // 总吞吐量
		double total_drop_rate;	   // 总丢包率%
		uint64_t total_output_rps; // 总输出记录/秒
		uint32_t online_users;	   // 在线用户数
		uint32_t active_flows;	   // 活跃流数
		bool has_alert;			   // 是否有告警
	};
	SystemSummary getLastSummary() const;

private:
	// ── 主循环 ───────────────────────────────────────────
	void run();

	// ── 定期任务 ─────────────────────────────────────────
	void doReport(uint64_t now_ms, uint64_t elapsed_ms);
	void doStallCheck(uint64_t now_ms);
	void doNicReport(uint64_t now_ms, uint64_t elapsed_ms);
	void doQueueCheck();
	void doSysCheck();

	// ── 统计计算 ─────────────────────────────────────────
	// 计算单线程速率（包/秒、Gbps、丢包率）
	struct RateStats
	{
		double pps;
		double gbps;
		double drop_rate_pct;
		double output_rps;
	};
	RateStats calcRate(const ThreadStats &stats,
					   ThreadHealthSnapshot &snap,
					   uint64_t elapsed_ms) const;

	// ── Stall检测 ─────────────────────────────────────────
	// 返回true表示线程stall
	bool isStalled(const ThreadStats &stats,
				   ThreadHealthSnapshot &snap,
				   uint64_t total_nic_pps) const;

	// ── NIC统计 ───────────────────────────────────────────
	void collectNicStats(uint16_t port_id,
						 NicSnapshot &snap_out);

	// ── 系统资源检查 ──────────────────────────────────────
	double readCpuUsage(); // 读取 /proc/stat
	double readMemUsage(); // 读取 /proc/meminfo

	// ── 格式化输出辅助 ────────────────────────────────────
	static std::string fmtBps(double bps);	// "12.34 Gbps"
	static std::string fmtRate(double pct); // "0.012%"

	// ── 告警辅助 ──────────────────────────────────────────
	void alertDropRate(double rate, const std::string &name);
	void alertStall(const std::string &name, uint32_t lcore_id);
	void alertQueueFull(const std::string &queue_name, float fill);

	// ── 线程注册表 ────────────────────────────────────────
	struct RxEntry
	{
		RxThread *thread;
		uint32_t lcore_id;
		ThreadHealthSnapshot snap;
	};
	struct WorkerEntry
	{
		WorkerThread *thread;
		uint32_t lcore_id;
		ThreadHealthSnapshot snap;
		uint32_t restart_count = 0;
		uint64_t last_restart_ms = 0;
	};

	std::vector<RxEntry> rx_entries_;
	std::vector<WorkerEntry> worker_entries_;
	RadiusThread *radius_thread_ = nullptr;
	OutputThread *output_thread_ = nullptr;
	FlowDispatcher *dispatcher_ = nullptr;

	ThreadHealthSnapshot radius_snap_;
	ThreadHealthSnapshot output_snap_;

	// ── NIC快照（每个端口一份）────────────────────────────
	static constexpr uint8_t MAX_PORTS = 4;
	NicSnapshot nic_snaps_[MAX_PORTS] = {};

	// ── CPU利用率（/proc/stat）────────────────────────────
	struct CpuStat
	{
		uint64_t user = 0, nice = 0, system = 0,
				 idle = 0, iowait = 0, irq = 0, softirq = 0;
		uint64_t total() const
		{
			return user + nice + system + idle + iowait + irq + softirq;
		}
		uint64_t active() const
		{
			return user + nice + system + irq + softirq;
		}
	};
	CpuStat cpu_snap_prev_;

	// ── 时间追踪 ──────────────────────────────────────────
	uint64_t last_report_ms_ = 0;
	uint64_t last_stall_ms_ = 0;
	uint64_t last_nic_ms_ = 0;

	// ── 摘要（原子写，外部只读）──────────────────────────
	mutable std::atomic<double> summary_rx_pps_{0};
	mutable std::atomic<double> summary_rx_gbps_{0};
	mutable std::atomic<double> summary_drop_rate_{0};
	mutable std::atomic<uint64_t> summary_output_rps_{0};
	mutable std::atomic<bool> summary_has_alert_{false};

	// ── 成员 ─────────��───────────────────────────────────
	Config cfg_;
	std::atomic<bool> running_{true};
	std::atomic<ThreadState> state_{ThreadState::IDLE};
	std::thread thread_;
};