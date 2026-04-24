#include "output_thread.h"
#include "worker_thread.h"   // WorkerOutputQueues 完整定义

#include "../utils/time_utils.h"
#include <unistd.h>
#include <cstring>
#include <ctime>
#include <spdlog/spdlog.h>

// ─────────────────────────────────────────────────────────
// 构造 / 析构
// ─────────────────────────────────────────────────────────
OutputThread::OutputThread(const OutputThreadConfig& cfg)
    : cfg_(cfg)
{
    file_manager_ = std::make_unique<RawFileManager>(
        cfg_.raw_dir, cfg_.collector_id);

    memset(worker_queues_, 0, sizeof(worker_queues_));
    memset(signal_queues_, 0, sizeof(signal_queues_));
}

OutputThread::~OutputThread() {
    if (running_.load()) stop();
    if (thread_.joinable()) thread_.join();
}

// ─────────────────────────────────────────────────────────
// 注册队列
// ─────────────────────────────────────────────────────────
void OutputThread::registerWorkerQueues(WorkerOutputQueues* wq) {
    if (!wq) return;
    uint16_t idx = worker_count_.fetch_add(
        1, std::memory_order_relaxed);
    if (idx >= MAX_WORKERS) {
        worker_count_.fetch_sub(1, std::memory_order_relaxed);
        spdlog::error("[OutputThread] too many workers, max={}",
                      MAX_WORKERS);
        return;
    }
    worker_queues_[idx] = wq;
    spdlog::info("[OutputThread] registered worker queue #{}",
                 idx);
}

void OutputThread::registerSignalQueues(SignalOutputQueues* sq) {
    if (!sq) return;
    uint8_t idx = signal_count_.fetch_add(
        1, std::memory_order_relaxed);
    if (idx >= MAX_SIGNAL_QUEUES) {
        signal_count_.fetch_sub(1, std::memory_order_relaxed);
        spdlog::error("[OutputThread] too many signal queues, max={}",
                      MAX_SIGNAL_QUEUES);
        return;
    }
    signal_queues_[idx] = sq;
    spdlog::info("[OutputThread] registered signal queue #{}",
                 idx);
}

// ─────────────────────────────────────────────────────────
// 生命周期
// ─────────────────────────────────────────────────────────
void OutputThread::start() {
    running_.store(true, std::memory_order_relaxed);
    thread_ = std::thread(&OutputThread::run, this);
    spdlog::info("[OutputThread] started, raw_dir={} rotate={}s",
                 cfg_.raw_dir, cfg_.rotate_interval);
}

void OutputThread::stop() {
    running_.store(false, std::memory_order_relaxed);
    spdlog::info("[OutputThread] stop requested");
}

void OutputThread::join() {
    if (thread_.joinable()) thread_.join();
}

// ─────────────────────────────────────────────────────────
// 文件轮转
// ─────────────────────────────────────────────────────────
void OutputThread::rotateIfNeeded(uint64_t now_us) {
    uint32_t now_sec = (uint32_t)(now_us / 1000000);
    uint32_t min_ts  = now_sec -
                       (now_sec % cfg_.rotate_interval);
    if (min_ts <= last_rotate_min_) return;

    spdlog::info("[OutputThread] rotating files, min_ts={}",
                 min_ts);
    file_manager_->rotateIfNeeded(min_ts);
    last_rotate_min_ = min_ts;
}

// ─────────────────────────────────────────────────────────
// 各协议写入
// ─────────────────────────────────────────────────────────
void OutputThread::writeTcpRecord(const TcpSessionRecord& r) {
    file_manager_->writeTcp(r);
    stat_tcp_.fetch_add(1, std::memory_order_relaxed);
}

void OutputThread::writeHttpRecord(const HttpRecord& r) {
    file_manager_->writeHttp(r);
    stat_http_.fetch_add(1, std::memory_order_relaxed);
}

void OutputThread::writeOnuRecord(const OnuRecord& r) {
    file_manager_->writeOnu(r);
    stat_onu_.fetch_add(1, std::memory_order_relaxed);
}

void OutputThread::writeRadiusRecord(const RadiusRecord& r) {
    file_manager_->writeRadius(r);
    stat_radius_.fetch_add(1, std::memory_order_relaxed);
}

void OutputThread::writePppoeRecord(const PPPoERecord& r) {
    file_manager_->writePPPoE(r);
    stat_pppoe_.fetch_add(1, std::memory_order_relaxed);
}

void OutputThread::writeDnsRecord(const DnsRecord& r) {
    file_manager_->writeDns(r);
    stat_dns_.fetch_add(1, std::memory_order_relaxed);
}

void OutputThread::writeUdpRecord(const UdpStreamRecord& r) {
    file_manager_->writeUdp(r);
    stat_udp_.fetch_add(1, std::memory_order_relaxed);
}

// ─────────────────────────────────────────────────────────
// 消费 Worker 队列（TCP / HTTP / ONU / DNS / UDP）
// ─────────────────────────────────────────────────────────
uint32_t OutputThread::drainWorkerQueues(WorkerOutputQueues* wq) {
    uint32_t total = 0;
    uint32_t batch = cfg_.drain_batch;

    { // TCP
        TcpSessionRecord r;
        uint32_t cnt = 0;
        while (cnt < batch && wq->tcp_q.pop(r)) {
            writeTcpRecord(r); ++cnt;
        }
        total += cnt;
    }
    { // HTTP
        HttpRecord r;
        uint32_t cnt = 0;
        while (cnt < batch && wq->http_q.pop(r)) {
            writeHttpRecord(r); ++cnt;
        }
        total += cnt;
    }
    { // ONU
        OnuRecord r;
        uint32_t cnt = 0;
        while (cnt < batch && wq->onu_q.pop(r)) {
            writeOnuRecord(r); ++cnt;
        }
        total += cnt;
    }
    { // DNS
        DnsRecord r;
        uint32_t cnt = 0;
        while (cnt < batch && wq->dns_q.pop(r)) {
            writeDnsRecord(r); ++cnt;
        }
        total += cnt;
    }
    { // UDP
        UdpStreamRecord r;
        uint32_t cnt = 0;
        while (cnt < batch && wq->udp_q.pop(r)) {
            writeUdpRecord(r); ++cnt;
        }
        total += cnt;
    }

    return total;
}

// ─────────────────────────────────────────────────────────
// 消费 Signal 队列（Radius / PPPoE）
// ─────────────────────────────────────────────────────────
uint32_t OutputThread::drainSignalQueues(SignalOutputQueues* sq) {
    uint32_t total = 0;
    uint32_t batch = cfg_.drain_batch;

    { // Radius
        RadiusRecord r;
        uint32_t cnt = 0;
        while (cnt < batch && sq->radius_q.pop(r)) {
            writeRadiusRecord(r); ++cnt;
        }
        total += cnt;
    }
    { // PPPoE
        PPPoERecord r;
        uint32_t cnt = 0;
        while (cnt < batch && sq->pppoe_q.pop(r)) {
            writePppoeRecord(r); ++cnt;
        }
        total += cnt;
    }

    return total;
}

// ─────────────────────────────────────────────────────────
// 主循环
// ─────────────────────────────────────────────────────────
void OutputThread::run() {
    state_.store(ThreadState::RUNNING,
                 std::memory_order_relaxed);
    spdlog::info("[OutputThread] run() entered");

    // 初始化文件轮转时间戳
    {
        time_t now = time(nullptr);
        last_rotate_min_ =
            (uint32_t)(now - now % cfg_.rotate_interval);
        file_manager_->rotateIfNeeded(last_rotate_min_);
    }

    static constexpr uint64_t LOG_INTERVAL_US =
        60ULL * 1000000;
    uint64_t last_log_us = 0;

    while (running_.load(std::memory_order_relaxed)) {

        // ── 当前时间 ──────────────────────────────────────
        struct timespec ts{};
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t now_us = (uint64_t)ts.tv_sec * 1000000
                        + (uint64_t)ts.tv_nsec / 1000;

        // ── 文件轮转检查 ──────────────────────────────────
        rotateIfNeeded(now_us);

        // ── 消费所有队��� ──────────────────────────────────
        uint32_t total = 0;

        uint16_t nb_workers =
            worker_count_.load(std::memory_order_relaxed);
        for (uint16_t i = 0; i < nb_workers; ++i) {
            if (worker_queues_[i])
                total += drainWorkerQueues(worker_queues_[i]);
        }

        uint8_t nb_signal =
            signal_count_.load(std::memory_order_relaxed);
        for (uint8_t i = 0; i < nb_signal; ++i) {
            if (signal_queues_[i])
                total += drainSignalQueues(signal_queues_[i]);
        }

        // ── 空转休眠 ──────────────────────────────────────
        if (total == 0)
            usleep(cfg_.idle_sleep_us);

        // ── 定期统计日志 ──────────────────────────────────
        if (now_us - last_log_us > LOG_INTERVAL_US) {
            spdlog::info(
                "[OutputThread] stats: "
                "tcp={} http={} onu={} "
                "radius={} pppoe={} "
                "dns={} udp={} drop={}",
                stat_tcp_.load(),    stat_http_.load(),
                stat_onu_.load(),    stat_radius_.load(),
                stat_pppoe_.load(),  stat_dns_.load(),
                stat_udp_.load(),    stat_drop_.load());
            last_log_us = now_us;
        }
    }

    // ── 退出前 flush 所有剩余记录 ─────────────────────────
    spdlog::info("[OutputThread] flushing remaining records...");
    {
        bool any = true;
        while (any) {
            any = false;

            uint16_t nb_w =
                worker_count_.load(std::memory_order_relaxed);
            for (uint16_t i = 0; i < nb_w; ++i) {
                if (worker_queues_[i] &&
                    drainWorkerQueues(worker_queues_[i]) > 0)
                    any = true;
            }

            uint8_t nb_s =
                signal_count_.load(std::memory_order_relaxed);
            for (uint8_t i = 0; i < nb_s; ++i) {
                if (signal_queues_[i] &&
                    drainSignalQueues(signal_queues_[i]) > 0)
                    any = true;
            }
        }
    }

    file_manager_->flushAll();
    file_manager_->shutdown();

    state_.store(ThreadState::STOPPED,
                 std::memory_order_relaxed);
    spdlog::info(
        "[OutputThread] stopped. final stats: "
        "tcp={} http={} onu={} "
        "radius={} pppoe={} "
        "dns={} udp={}",
        stat_tcp_.load(),   stat_http_.load(),
        stat_onu_.load(),   stat_radius_.load(),
        stat_pppoe_.load(), stat_dns_.load(),
        stat_udp_.load());
}
