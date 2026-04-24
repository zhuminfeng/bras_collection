#include "monitor_thread.h"

#include "rx_thread.h"
#include "worker_thread.h"
#include "radius_thread.h"
#include "output_thread.h"
#include "../core/flow_dispatcher.h"
#include "../core/dpdk_engine.h"

#include <rte_ethdev.h>
#include <rte_launch.h>
#include <rte_cycles.h>

#include <spdlog/spdlog.h>

#include <chrono>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <stdexcept>

// ─────────────────────────────────────────────────────────
// 获取当前时间(ms)
// ─────────────────────────────────────────────────────────
static uint64_t nowMs()
{
	return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
			   std::chrono::steady_clock::now().time_since_epoch())
		.count();
}

// ─────────────────────────────────────────────────────────
// 构造/析构
// ─────────────────────────────────────────────────────────
MonitorThread::MonitorThread(const Config &cfg)
	: cfg_(cfg)
{
	memset(nic_snaps_, 0, sizeof(nic_snaps_));
	memset(&cpu_snap_prev_, 0, sizeof(cpu_snap_prev_));
}

MonitorThread::~MonitorThread()
{
	stop();
	join();
}

// ─────────────────────────────────────────────────────────
// 注册
// ─────────────────────────────────────────────────────────
void MonitorThread::registerRx(RxThread *t, uint32_t lcore_id)
{
	rx_entries_.push_back({t, lcore_id, {}});
}

void MonitorThread::registerWorker(WorkerThread *t, uint32_t lcore_id)
{
	worker_entries_.push_back({t, lcore_id, {}, 0, 0});
}

void MonitorThread::registerRadius(RadiusThread *t)
{
	radius_thread_ = t;
}

void MonitorThread::registerOutput(OutputThread *t)
{
	output_thread_ = t;
}

void MonitorThread::setDispatcher(FlowDispatcher *d)
{
	dispatcher_ = d;
}

// ─────────────────────────────────────────────────────────
// 生命周期
// ─────────────────────────────────────────────────────────
void MonitorThread::start()
{
	thread_ = std::thread(&MonitorThread::run, this);
}

void MonitorThread::stop()
{
	running_.store(false, std::memory_order_relaxed);
}

void MonitorThread::join()
{
	if (thread_.joinable())
		thread_.join();
}

// ─────────────────────────────────────────────────────────
// 主循环
// ─────────────────────────────────────────────────────────
void MonitorThread::run()
{
	state_.store(ThreadState::RUNNING, std::memory_order_relaxed);
	spdlog::info("[Monitor] started. "
				 "report={}s stall={}s drop_warn={:.1f}%",
				 cfg_.report_interval_sec,
				 cfg_.stall_check_sec,
				 cfg_.drop_rate_warn_pct);

	// 初始化时间
	uint64_t start_ms = nowMs();
	last_report_ms_ = start_ms;
	last_stall_ms_ = start_ms;
	last_nic_ms_ = start_ms;

	// 预读CPU基线
	readCpuUsage();

	// 初始化NIC快照基线
	uint16_t port_id;
	RTE_ETH_FOREACH_DEV(port_id)
	{
		if (port_id < MAX_PORTS)
			collectNicStats(port_id, nic_snaps_[port_id]);
	}

	// 初始化线程快照基线
	for (auto &e : rx_entries_)
	{
		e.snap.rx_pkts = e.thread->stats().rx_pkts.load();
		e.snap.rx_bytes = e.thread->stats().rx_bytes.load();
		e.snap.drop_pkts = e.thread->stats().drop_pkts.load();
	}
	for (auto &e : worker_entries_)
	{
		e.snap.rx_pkts = e.thread->stats().rx_pkts.load();
		e.snap.rx_bytes = e.thread->stats().rx_bytes.load();
		e.snap.drop_pkts = e.thread->stats().drop_pkts.load();
		e.snap.output_records = e.thread->stats().output_records.load();
	}
	if (radius_thread_)
	{
		radius_snap_.rx_pkts = radius_thread_->stats().rx_pkts.load();
	}
	if (output_thread_)
	{
		output_snap_.output_records =
			output_thread_->stats().output_records.load();
	}

	// ── 主循环：1秒一次轮询 ───────────────────────────────
	while (running_.load(std::memory_order_relaxed))
	{
		std::this_thread::sleep_for(std::chrono::seconds(1));

		uint64_t now = nowMs();

		// ── 统计打印（每 report_interval_sec 秒）──────────
		uint64_t elapsed_report = now - last_report_ms_;
		if (elapsed_report >= (uint64_t)cfg_.report_interval_sec * 1000)
		{
			doReport(now, elapsed_report);
			doNicReport(now, elapsed_report);
			doSysCheck();
			doQueueCheck();
			last_report_ms_ = now;
		}

		// ── Stall检测（每 stall_check_sec 秒）────────────
		uint64_t elapsed_stall = now - last_stall_ms_;
		if (elapsed_stall >= (uint64_t)cfg_.stall_check_sec * 1000)
		{
			doStallCheck(now);
			last_stall_ms_ = now;
		}
	}

	state_.store(ThreadState::STOPPED, std::memory_order_relaxed);
	spdlog::info("[Monitor] stopped");
}

// ─────────────────────────────────────────────────────────
// 统计打印
// ─────────────────────────────────────────────────────────
void MonitorThread::doReport(uint64_t now_ms, uint64_t elapsed_ms)
{
	if (elapsed_ms == 0)
		elapsed_ms = 1;

	double total_rx_pps = 0;
	double total_rx_gbps = 0;
	double total_drop_rate = 0;
	uint64_t total_out_rps = 0;
	bool has_alert = false;

	spdlog::info("════════════════════════════════════════"
				 "═══════════════════════════");
	spdlog::info("[Monitor] === Report (interval={}ms) ===",
				 elapsed_ms);

	// ── Rx线程统计 ────────────────────────────────────────
	for (size_t i = 0; i < rx_entries_.size(); ++i)
	{
		auto &e = rx_entries_[i];
		auto r = calcRate(e.thread->stats(), e.snap, elapsed_ms);

		spdlog::info(
			"[Rx #{}] lcore={} pps={:.0f} {} drop={} "
			"running={}",
			i, e.lcore_id,
			r.pps,
			fmtBps(r.gbps * 1e9),
			fmtRate(r.drop_rate_pct),
			e.thread->isRunning() ? "YES" : "NO");

		total_rx_pps += r.pps;
		total_rx_gbps += r.gbps;

		if (r.drop_rate_pct >= cfg_.drop_rate_warn_pct)
		{
			alertDropRate(r.drop_rate_pct,
						  "Rx#" + std::to_string(i));
			has_alert = true;
		}
	}

	// ── Worker线程统计 ────────────────────────────────────
	for (size_t i = 0; i < worker_entries_.size(); ++i)
	{
		auto &e = worker_entries_[i];
		auto r = calcRate(e.thread->stats(), e.snap, elapsed_ms);

		spdlog::info(
			"[Worker #{}] lcore={} pps={:.0f} out={:.0f}/s "
			"drop={} tcp={} http={} dns={} running={}",
			i, e.lcore_id,
			r.pps,
			r.output_rps,
			fmtRate(r.drop_rate_pct),
			e.thread->stats().tcp_sessions.load(),
			e.thread->stats().http_records.load(),
			e.thread->stats().dns_records.load(),
			e.thread->isRunning() ? "YES" : "NO");

		total_out_rps += (uint64_t)r.output_rps;

		if (r.drop_rate_pct >= cfg_.drop_rate_warn_pct)
		{
			alertDropRate(r.drop_rate_pct,
						  "Worker#" + std::to_string(i));
			has_alert = true;
		}
	}

	// ── Radius线程统计 ────────────────────────────────────
	if (radius_thread_)
	{
		uint64_t cur_rx = radius_thread_->stats()
							  .rx_pkts.load(std::memory_order_relaxed);
		uint64_t delta = cur_rx - radius_snap_.rx_pkts;
		double pps = (double)delta / (elapsed_ms / 1000.0);

		spdlog::info(
			"[Radius] pps={:.0f} parsed={} pppoe={} "
			"errors={} online_users={} running={}",
			pps,
			radius_thread_->radiusParsed(),
			radius_thread_->pppoeParsed(),
			radius_thread_->parseErrors(),
			radius_thread_->onlineUsers(),
			radius_thread_->isRunning() ? "YES" : "NO");

		radius_snap_.rx_pkts = cur_rx;
	}

	// ── Output线程统计 ────────────────────────────────────
	if (output_thread_)
	{
		uint64_t cur_out = output_thread_->stats()
							   .output_records.load(std::memory_order_relaxed);
		uint64_t delta = cur_out - output_snap_.output_records;
		double rps = (double)delta / (elapsed_ms / 1000.0);

		auto depth = output_thread_->getQueueDepth();
		spdlog::info(
			"[Output] rps={:.0f} total={} "
			"q_http={} q_tcp={} q_dns={} q_udp={} "
			"q_radius={} running={}",
			rps, cur_out,
			depth.http_total,
			depth.tcp_total,
			depth.dns_total,
			depth.udp_total,
			depth.radius,
			output_thread_->isRunning() ? "YES" : "NO");

		output_snap_.output_records = cur_out;
		total_out_rps = (uint64_t)rps;
	}

	// ── 分流器统计 ────────────────────────────────────────
	if (dispatcher_)
	{
		spdlog::info(
			"[Dispatcher] radius={} pppoe={} user={} drop={}",
			dispatcher_->getRadiusCount(),
			dispatcher_->getPPPoECount(),
			dispatcher_->getUserCount(),
			dispatcher_->getDropCount());

		uint64_t total = dispatcher_->getUserCount() + dispatcher_->getRadiusCount() + dispatcher_->getPPPoECount() + dispatcher_->getDropCount();
		if (total > 0)
		{
			total_drop_rate = dispatcher_->getDropCount() * 100.0 / (double)total;
		}
	}

	// ── 总体汇总 ──────────────────────────────────────────
	spdlog::info(
		"[TOTAL] rx_pps={:.0f} {} drop={} out_rps={} alert={}",
		total_rx_pps,
		fmtBps(total_rx_gbps * 1e9),
		fmtRate(total_drop_rate),
		total_out_rps,
		has_alert ? "YES" : "no");

	spdlog::info("════════════════════════════════════════"
				 "═══════════════════════════");

	// 更新摘要原子变量
	summary_rx_pps_.store(total_rx_pps, std::memory_order_relaxed);
	summary_rx_gbps_.store(total_rx_gbps, std::memory_order_relaxed);
	summary_drop_rate_.store(total_drop_rate, std::memory_order_relaxed);
	summary_output_rps_.store(total_out_rps, std::memory_order_relaxed);
	summary_has_alert_.store(has_alert, std::memory_order_relaxed);
}

// ─────────────────────────────────────────────────────────
// NIC硬件统计（imissed/ierrors 是丢包的根本来源）
// ─────────────────────────────────────────────────────────
void MonitorThread::doNicReport(uint64_t now_ms, uint64_t elapsed_ms)
{
	if (elapsed_ms == 0)
		elapsed_ms = 1;

	uint16_t port_id;
	RTE_ETH_FOREACH_DEV(port_id)
	{
		if (port_id >= MAX_PORTS)
			break;

		NicSnapshot cur{};
		collectNicStats(port_id, cur);

		NicSnapshot &prev = nic_snaps_[port_id];

		uint64_t d_rx = cur.ipackets - prev.ipackets;
		uint64_t d_missed = cur.imissed - prev.imissed;
		uint64_t d_err = cur.ierrors - prev.ierrors;
		uint64_t d_bytes = cur.ibytes - prev.ibytes;

		double rx_pps = (double)d_rx / (elapsed_ms / 1000.0);
		double miss_pps = (double)d_missed / (elapsed_ms / 1000.0);
		double rx_gbps = (double)d_bytes * 8.0 / (elapsed_ms / 1000.0) / 1e9;

		double miss_rate = (d_rx + d_missed) > 0
							   ? d_missed * 100.0 / (double)(d_rx + d_missed)
							   : 0.0;

		spdlog::info(
			"[NIC port{}] rx_pps={:.0f} {} "
			"missed_pps={:.0f} missed_rate={} err={}",
			port_id,
			rx_pps, fmtBps(rx_gbps * 1e9),
			miss_pps, fmtRate(miss_rate),
			d_err);

		// NIC级别丢包告警
		if (miss_rate >= cfg_.drop_rate_crit_pct)
		{
			spdlog::critical(
				"[NIC port{}] CRITICAL: NIC missed rate {:.2f}% "
				"> {:.1f}%! Ring buffer too small or CPU overloaded.",
				port_id, miss_rate, cfg_.drop_rate_crit_pct);
			summary_has_alert_.store(true, std::memory_order_relaxed);
		}
		else if (miss_rate >= cfg_.drop_rate_warn_pct)
		{
			spdlog::warn(
				"[NIC port{}] WARNING: NIC missed rate {:.2f}%",
				port_id, miss_rate);
		}

		prev = cur;
	}
}

// ─────────────────────────────────────────────────────────
// Stall检测：线程是否挂起
// 判断条件：全局有足够流量 && 该线程包数长时间不增长
// ─────────────────────────────────────────────────────────
void MonitorThread::doStallCheck(uint64_t now_ms)
{
	// 计算全局NIC收包速率（判断是否有足够流量）
	uint64_t total_nic_pkts_delta = 0;
	uint16_t port_id;
	RTE_ETH_FOREACH_DEV(port_id)
	{
		if (port_id >= MAX_PORTS)
			break;
		NicSnapshot cur{};
		rte_eth_stats eth{};
		rte_eth_stats_get(port_id, &eth);
		total_nic_pkts_delta += eth.ipackets;
	}
	// 简化：用累计包数估算，只要 > 阈值就认为有流量
	uint64_t total_nic_pps =
		(total_nic_pkts_delta > 0)
			? total_nic_pkts_delta / std::max((uint64_t)1,
											  (now_ms - last_stall_ms_) / 1000)
			: 0;

	bool any_stall = false;

	// ── 检查 Rx 线程 ──────────────────────────────────────
	for (size_t i = 0; i < rx_entries_.size(); ++i)
	{
		auto &e = rx_entries_[i];
		if (!e.thread->isRunning())
		{
			spdlog::error("[Monitor] Rx#{} NOT running! lcore={}",
						  i, e.lcore_id);
			any_stall = true;
			// Rx线程不支持热重启（需要重新launch lcore）
			// 只记录告警，由运维人员处理
			alertStall("Rx#" + std::to_string(i), e.lcore_id);
			continue;
		}

		if (isStalled(e.thread->stats(), e.snap, total_nic_pps))
		{
			spdlog::error(
				"[Monitor] Rx#{} STALLED! lcore={} "
				"no packets for {}s",
				i, e.lcore_id, cfg_.stall_check_sec);
			alertStall("Rx#" + std::to_string(i), e.lcore_id);
			any_stall = true;
		}
	}

	// ── 检查 Worker 线程 ──────────────────────────────────
	for (size_t i = 0; i < worker_entries_.size(); ++i)
	{
		auto &e = worker_entries_[i];
		if (!e.thread->isRunning())
		{
			spdlog::error("[Monitor] Worker#{} NOT running! lcore={}",
						  i, e.lcore_id);
			alertStall("Worker#" + std::to_string(i), e.lcore_id);
			any_stall = true;

			if (cfg_.enable_restart)
			{
				// 防止频繁重启（最少间隔60s）
				constexpr uint64_t MIN_RESTART_INTERVAL_MS = 60000;
				if (now_ms - e.last_restart_ms > MIN_RESTART_INTERVAL_MS)
				{
					spdlog::warn(
						"[Monitor] Restarting Worker#{} "
						"(restart_count={})",
						i, e.restart_count);
					e.thread->restart();
					++e.restart_count;
					e.last_restart_ms = now_ms;
				}
				else
				{
					spdlog::warn(
						"[Monitor] Worker#{} restart suppressed "
						"(too frequent, last={}ms ago)",
						i, now_ms - e.last_restart_ms);
				}
			}
			continue;
		}

		if (isStalled(e.thread->stats(), e.snap, total_nic_pps))
		{
			spdlog::error(
				"[Monitor] Worker#{} STALLED! lcore={} "
				"no packets for {}s (restart_count={})",
				i, e.lcore_id, cfg_.stall_check_sec,
				e.restart_count);
			alertStall("Worker#" + std::to_string(i), e.lcore_id);
			any_stall = true;

			if (cfg_.enable_restart)
			{
				constexpr uint64_t MIN_RESTART_INTERVAL_MS = 60000;
				if (now_ms - e.last_restart_ms > MIN_RESTART_INTERVAL_MS)
				{
					spdlog::warn("[Monitor] Restarting Worker#{}...", i);
					e.thread->restart();
					++e.restart_count;
					e.last_restart_ms = now_ms;
				}
			}
		}
	}

	// ── 检查 Radius 线程 ──────────────────────────────────
	if (radius_thread_ && !radius_thread_->isRunning())
	{
		spdlog::error("[Monitor] RadiusThread NOT running!");
		alertStall("RadiusThread", 0);
		any_stall = true;
	}

	// ── 检查 Output 线程 ──────────────────────────────────
	if (output_thread_ && !output_thread_->isRunning())
	{
		spdlog::critical(
			"[Monitor] OutputThread NOT running! "
			"All DCS output has stopped!");
		alertStall("OutputThread", 0);
		any_stall = true;
	}

	if (!any_stall)
	{
		spdlog::debug("[Monitor] Stall check OK, all threads alive");
	}

	if (any_stall)
		summary_has_alert_.store(true, std::memory_order_relaxed);
}

// ─────────────────────────────────────────────────────────
// 队列水位检查
// ─────��───────────────────────────────────────────────────
void MonitorThread::doQueueCheck()
{
	if (!output_thread_)
		return;

	auto depth = output_thread_->getQueueDepth();

	// HTTP队列水位（相对于单个Worker的队列容量）
	float http_fill = (float)depth.http_total / (float)(HTTP_QUEUE_CAP *
														std::max((uint16_t)1,
																 (uint16_t)worker_entries_.size()));
	if (http_fill >= cfg_.queue_warn_level)
	{
		alertQueueFull("http_q", http_fill);
		summary_has_alert_.store(true, std::memory_order_relaxed);
	}

	float radius_fill = (float)depth.radius / (float)RADIUS_QUEUE_CAP;
	if (radius_fill >= cfg_.queue_warn_level)
	{
		alertQueueFull("radius_q", radius_fill);
	}

	float dns_fill = (float)depth.dns_total / (float)(DNS_QUEUE_CAP *
													  std::max((uint16_t)1,
															   (uint16_t)worker_entries_.size()));
	if (dns_fill >= cfg_.queue_warn_level)
	{
		alertQueueFull("dns_q", dns_fill);
	}
}

// ─────────────────────────────────────────────────────────
// 系统资源检查（CPU/内存）
// ─────────────────────────────────────────────────────────
void MonitorThread::doSysCheck()
{
	double cpu_pct = readCpuUsage();
	double mem_pct = readMemUsage();

	spdlog::info("[SysCheck] cpu={:.1f}% mem={:.1f}%",
				 cpu_pct, mem_pct);

	if (cpu_pct > 95.0)
	{
		spdlog::warn("[Monitor] CPU usage {:.1f}% > 95%! "
					 "May cause packet drops.",
					 cpu_pct);
		summary_has_alert_.store(true, std::memory_order_relaxed);
	}
	if (mem_pct > 90.0)
	{
		spdlog::warn("[Monitor] Memory usage {:.1f}% > 90%!",
					 mem_pct);
	}
}

// ─────────────────────────────────────────────────────────
// 速率计算
// ─────────────────────────────────────────────────────────
MonitorThread::RateStats MonitorThread::calcRate(
	const ThreadStats &stats,
	ThreadHealthSnapshot &snap,
	uint64_t elapsed_ms) const
{
	RateStats r{};
	if (elapsed_ms == 0)
		return r;

	double secs = elapsed_ms / 1000.0;

	uint64_t cur_rx = stats.rx_pkts.load(std::memory_order_relaxed);
	uint64_t cur_drop = stats.drop_pkts.load(std::memory_order_relaxed);
	uint64_t cur_bytes = stats.rx_bytes.load(std::memory_order_relaxed);
	uint64_t cur_out = stats.output_records.load(std::memory_order_relaxed);

	uint64_t d_rx = cur_rx - snap.rx_pkts;
	uint64_t d_drop = cur_drop - snap.drop_pkts;
	uint64_t d_bytes = cur_bytes - snap.rx_bytes;
	uint64_t d_out = cur_out - snap.output_records;

	r.pps = (double)d_rx / secs;
	r.gbps = (double)d_bytes * 8.0 / secs / 1e9;
	r.output_rps = (double)d_out / secs;
	r.drop_rate_pct = (d_rx + d_drop) > 0
						  ? d_drop * 100.0 / (double)(d_rx + d_drop)
						  : 0.0;

	// 更新快照
	snap.rx_pkts = cur_rx;
	snap.drop_pkts = cur_drop;
	snap.rx_bytes = cur_bytes;
	snap.output_records = cur_out;

	return r;
}

// ─────────────────────────────────────────────────────────
// Stall判断：
//   条件1：NIC有足够流量（total_nic_pps > min阈值）
//   条件2：该线程在检查周期内包数增量为0
// ─────────────────────────────────────────────────────────
bool MonitorThread::isStalled(const ThreadStats &stats,
							  ThreadHealthSnapshot &snap,
							  uint64_t total_nic_pps) const
{
	// NIC没有足够流量时不判断stall
	if (total_nic_pps < cfg_.min_rx_pps_for_stall)
		return false;

	uint64_t cur_rx = stats.rx_pkts.load(std::memory_order_relaxed);
	uint64_t delta = cur_rx - snap.rx_pkts;

	// 更新快照（不影响 calcRate 里的快照，因为这里另行维护）
	// 注意：snap 同时被 calcRate 更新，此处只读
	return (delta == 0);
}

// ────────��────────────────────────────────────────────────
// NIC统计收集
// ─────────────────────────────────────────────────────────
void MonitorThread::collectNicStats(uint16_t port_id,
									NicSnapshot &snap_out)
{
	struct rte_eth_stats st{};
	rte_eth_stats_get(port_id, &st);
	snap_out.ipackets = st.ipackets;
	snap_out.opackets = st.opackets;
	snap_out.ibytes = st.ibytes;
	snap_out.imissed = st.imissed;
	snap_out.ierrors = st.ierrors;
}

// ─────────────────────────────────────────────────────────
// 读取系统CPU利用率（/proc/stat）
// ─────────────────────────────────────────────────────────
double MonitorThread::readCpuUsage()
{
	std::ifstream f("/proc/stat");
	if (!f.is_open())
		return -1.0;

	std::string line;
	std::getline(f, line); // 第一行：cpu总计

	CpuStat cur{};
	sscanf(line.c_str(),
		   "cpu %lu %lu %lu %lu %lu %lu %lu",
		   &cur.user, &cur.nice, &cur.system,
		   &cur.idle, &cur.iowait,
		   &cur.irq, &cur.softirq);

	uint64_t total_delta = cur.total() - cpu_snap_prev_.total();
	uint64_t active_delta = cur.active() - cpu_snap_prev_.active();

	double pct = (total_delta > 0)
					 ? (double)active_delta * 100.0 / (double)total_delta
					 : 0.0;

	cpu_snap_prev_ = cur;
	return pct;
}

// ─────────────────────────────────────────────────────────
// 读取内存利用率（/proc/meminfo）
// ─────────────────────────────────────────────────────────
double MonitorThread::readMemUsage()
{
	std::ifstream f("/proc/meminfo");
	if (!f.is_open())
		return -1.0;

	uint64_t mem_total = 0, mem_available = 0;
	std::string line;

	while (std::getline(f, line))
	{
		if (sscanf(line.c_str(), "MemTotal: %lu kB",
				   &mem_total) == 1)
			continue;
		if (sscanf(line.c_str(), "MemAvailable: %lu kB",
				   &mem_available) == 1)
			continue;
		if (mem_total && mem_available)
			break;
	}

	if (mem_total == 0)
		return -1.0;
	uint64_t used = mem_total - mem_available;
	return (double)used * 100.0 / (double)mem_total;
}

// ─────────────────────────────────────────────────────────
// 格式化输出辅助
// ─────────────────────────────────────────────────────────
std::string MonitorThread::fmtBps(double bps)
{
	char buf[32];
	if (bps >= 1e9)
		snprintf(buf, sizeof(buf), "%.2fGbps", bps / 1e9);
	else if (bps >= 1e6)
		snprintf(buf, sizeof(buf), "%.2fMbps", bps / 1e6);
	else if (bps >= 1e3)
		snprintf(buf, sizeof(buf), "%.2fKbps", bps / 1e3);
	else
		snprintf(buf, sizeof(buf), "%.0fbps", bps);
	return buf;
}

std::string MonitorThread::fmtRate(double pct)
{
	char buf[16];
	snprintf(buf, sizeof(buf), "%.4f%%", pct);
	return buf;
}

// ─────────────────────────────────────────────────────────
// 告警辅助
// ─────────────────────────────────────────────────────────
void MonitorThread::alertDropRate(double rate,
								  const std::string &name)
{
	if (rate >= cfg_.drop_rate_crit_pct)
	{
		spdlog::critical(
			"[ALERT] {} drop rate {:.3f}% >= critical threshold {:.1f}%",
			name, rate, cfg_.drop_rate_crit_pct);
	}
	else
	{
		spdlog::warn(
			"[ALERT] {} drop rate {:.3f}% >= warn threshold {:.1f}%",
			name, rate, cfg_.drop_rate_warn_pct);
	}
}

void MonitorThread::alertStall(const std::string &name,
							   uint32_t lcore_id)
{
	spdlog::error(
		"[ALERT] Thread {} (lcore={}) stalled or stopped! "
		"Check system load or hardware issues.",
		name, lcore_id);
}

void MonitorThread::alertQueueFull(const std::string &queue_name,
								   float fill)
{
	spdlog::warn(
		"[ALERT] Queue '{}' fill={:.1f}% >= {:.0f}%! "
		"OutputThread may be bottleneck.",
		queue_name, fill * 100.0f,
		cfg_.queue_warn_level * 100.0f);
}

// ─────────────────────────────────────────────────────────
// 外部访问：系统摘要
// ─────────────────────────────────────────────────────────
MonitorThread::SystemSummary MonitorThread::getLastSummary() const
{
	SystemSummary s{};
	s.total_rx_pps = summary_rx_pps_.load(std::memory_order_relaxed);
	s.total_rx_gbps = summary_rx_gbps_.load(std::memory_order_relaxed);
	s.total_drop_rate = summary_drop_rate_.load(std::memory_order_relaxed);
	s.total_output_rps = summary_output_rps_.load(std::memory_order_relaxed);
	s.has_alert = summary_has_alert_.load(std::memory_order_relaxed);
	s.online_users = radius_thread_
						 ? (uint32_t)radius_thread_->onlineUsers()
						 : 0;
	s.active_flows = 0; // 可扩展：从FlowTable聚合
	return s;
}