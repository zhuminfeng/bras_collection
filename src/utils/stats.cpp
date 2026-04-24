#include "stats.h"
#include <spdlog/spdlog.h>
#include <numeric>

void GlobalStats::registerThread(const std::string &name, ThreadStats *st)
{
	entries_.push_back({name, st});
}

void GlobalStats::printReport(uint32_t interval_sec)
{
	uint64_t total_rx = 0, total_drop = 0;
	uint64_t total_bytes = 0, total_out = 0;

	for (auto &e : entries_)
	{
		auto *s = e.stats;
		uint64_t rx = s->rx_pkts.load(std::memory_order_relaxed);
		uint64_t drop = s->drop_pkts.load(std::memory_order_relaxed);
		uint64_t bytes = s->rx_bytes.load(std::memory_order_relaxed);
		uint64_t out = s->output_records.load(std::memory_order_relaxed);

		uint64_t drx = rx - s->snap_prev.rx_pkts;
		uint64_t ddrop = drop - s->snap_prev.drop_pkts;
		uint64_t dbytes = bytes - s->snap_prev.rx_bytes;

		double pps = (double)drx / interval_sec;
		double bps = (double)dbytes * 8.0 / interval_sec;
		double drop_rate = drx > 0 ? ddrop * 100.0 / (drx + ddrop) : 0.0;

		spdlog::info("[{}] pps={:.0f} bps={:.2f}M drop={:.3f}% out={}",
					 e.name, pps, bps / 1e6, drop_rate, out);

		// 更新快照
		s->snap_prev.rx_pkts = rx;
		s->snap_prev.drop_pkts = drop;
		s->snap_prev.rx_bytes = bytes;
		s->snap_prev.output_records = out;

		total_rx += drx;
		total_drop += ddrop;
		total_bytes += dbytes;
		total_out += out;
	}

	double total_drop_rate = total_rx > 0
								 ? total_drop * 100.0 / (total_rx + total_drop)
								 : 0.0;
	cached_drop_rate_.store(total_drop_rate, std::memory_order_relaxed);

	spdlog::info("[TOTAL] pps={:.0f} throughput={:.2f}Gbps drop={:.3f}% records={}",
				 (double)total_rx / interval_sec,
				 (double)total_bytes * 8.0 / interval_sec / 1e9,
				 total_drop_rate,
				 total_out);

	if (total_drop_rate > 1.0)
	{
		spdlog::error("!!! DROP RATE {:.3f}% > 1% threshold !!!",
					  total_drop_rate);
	}
}

double GlobalStats::totalDropRate() const
{
	return cached_drop_rate_.load(std::memory_order_relaxed);
}