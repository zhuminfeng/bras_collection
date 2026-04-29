#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <arpa/inet.h>

#include <vector>
#include <memory>
#include <thread>
#include <chrono>
#include <csignal>
#include <cstring>
#include <stdexcept>

#include "utils/logger.h"
#include "utils/config.h"
#include "utils/stats.h"
#include "../include/common.h"

#include "core/dpdk_engine.h"
#include "core/ring_pool.h"
#include "core/flow_dispatcher.h"
#include "core/hw_flow_steering.h"

#include "threads/rx_thread.h"
#include "threads/radius_thread.h"
#include "threads/worker_thread.h"
#include "threads/output_thread.h"
#include "threads/monitor_thread.h"
#include "threads/signal_queues.h"   // ← 替代 radius_output_queues.h

#include "output/raw_file_manager.h"

// ─────────────────────────────────────────────────────────
// 全局退出标志
// ─────────────────────────────────────────────────────────
static volatile bool g_force_quit = false;

static void sigHandler(int sig) {
    spdlog::warn("Signal {} received, stopping collector...", sig);
    g_force_quit = true;
}

// ─────────────────────────────────────────────────────────
// LcoreAllocator：按需分配 DPDK worker lcore
// ─────────────────────────────────────────────────────────
class LcoreAllocator {
public:
    LcoreAllocator() {
        uint32_t lcore;
        RTE_LCORE_FOREACH_WORKER(lcore) {
            available_.push_back(lcore);
        }
        spdlog::info("[LcoreAllocator] available worker lcores: {}",
                     available_.size());
    }

    uint32_t alloc(const std::string& purpose) {
        if (idx_ >= available_.size())
            throw std::runtime_error(
                "No more lcores for: " + purpose +
                " (need more -l range in EAL args)");
        uint32_t lcore = available_[idx_++];
        spdlog::info("[LcoreAllocator] {} → lcore {}", purpose, lcore);
        return lcore;
    }

    size_t remaining() const {
        return available_.size() - idx_;
    }

private:
    std::vector<uint32_t> available_;
    size_t idx_ = 0;
};

// ─────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    Logger::init("./logs", 100, 10);
    spdlog::info("╔══════════════════════════════════════╗");
    spdlog::info("║  BRAS Collector starting...          ║");
    spdlog::info("╚══════════════════════════════════════╝");

    // ── 加载配置 ──────────────────────────────────────────
    CollectorConfig cfg;
    try {
        std::string cfg_path = "config/collector.json";
        for (int i = 1; i < argc; ++i) {
            if (strcmp(argv[i], "--") == 0 && i + 1 < argc) {
                cfg_path = argv[i + 1];
                break;
            }
        }
        cfg.load(cfg_path);
        cfg.validate();
        spdlog::info("[Config] loaded from {}", cfg_path);
    } catch (const std::exception& e) {
        spdlog::critical("[Config] load failed: {}", e.what());
        return 1;
    }

    // ── DPDK EAL 初始化 ───────────────────────────────────
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        spdlog::critical("[DPDK] rte_eal_init failed: {}",
                         rte_strerror(rte_errno));
        return 1;
    }
    spdlog::info("[DPDK] EAL initialized, main lcore={}",
                 rte_get_main_lcore());

    // ── DPDK 网口初始化 ───────────────────────────────────
    auto& dpdk = DpdkEngine::instance();
    try {
        dpdk.init(argc, argv, cfg.port_configs);
        spdlog::info("[DPDK] {} port(s) initialized",
                     cfg.port_configs.size());
    } catch (const std::exception& e) {
        spdlog::critical("[DPDK] port init failed: {}", e.what());
        rte_eal_cleanup();
        return 1;
    }

    // ── 创建 rte_ring ─────────────────────────────────────
    auto& ring_pool = RingPool::instance();
    struct rte_ring* radius_ring = nullptr;
    struct rte_ring* pppoe_ring  = nullptr;
    std::vector<struct rte_ring*> worker_rings;

    try {
        int socket_id = rte_eth_dev_socket_id(
            cfg.port_configs[0].port_id);

        radius_ring = ring_pool.createSpsc(
            "radius_ring", 4096, socket_id);

        pppoe_ring  = ring_pool.createSpsc(
            "pppoe_ring", 4096, socket_id);

        worker_rings = ring_pool.createWorkerRings(
            "worker_ring", cfg.nb_workers,
            RING_SIZE, socket_id);

        spdlog::info("[RingPool] created: radius_ring, pppoe_ring, "
                     "{} worker_rings (size={})",
                     worker_rings.size(), RING_SIZE);
    } catch (const std::exception& e) {
        spdlog::critical("[RingPool] ring create failed: {}", e.what());
        dpdk.shutdown();
        rte_eal_cleanup();
        return 1;
    }

    // ── FlowDispatcher ────────────────────────────────────
    DispatchConfig dcfg{};
    dcfg.bras_network       = cfg.bras_network;
    dcfg.bras_netmask       = cfg.bras_netmask;
    dcfg.radius_server_ips  = cfg.radius_ips;
    dcfg.radius_port        = cfg.radius_port;
    dcfg.nb_worker_queues   = cfg.nb_workers;

    auto dispatcher = std::make_shared<FlowDispatcher>(dcfg);
    dispatcher->setRadiusRing(radius_ring);
    dispatcher->setPPPoERing(pppoe_ring);
    dispatcher->setWorkerRings(worker_rings);

    // ── 硬件流分类（可选）────────────────────────────────
    std::unique_ptr<HwFlowSteering> hw_flow;
    if (cfg.hw_flow_steering) {
        hw_flow = std::make_unique<HwFlowSteering>(
            cfg.port_configs[0].port_id);
        if (hw_flow->isSupported()) {
            hw_flow->addRadiusRule(cfg.radius_queue);
            hw_flow->addPPPoERule(cfg.pppoe_queue);
            std::vector<uint16_t> wq_ids;
            for (uint16_t w = 0; w < cfg.nb_workers; ++w)
                wq_ids.push_back(cfg.worker_queue_start + w);
            hw_flow->addDefaultRssRule(wq_ids);
            spdlog::info("[HwFlow] hardware flow steering enabled");
        } else {
            spdlog::warn("[HwFlow] not supported, "
                         "fallback to SW dispatch");
        }
    }

    // ── 创建输出队列 ──────────────────────────────────────
    std::vector<std::unique_ptr<WorkerOutputQueues>> worker_out_queues;
    for (uint16_t w = 0; w < cfg.nb_workers; ++w)
        worker_out_queues.push_back(
            std::make_unique<WorkerOutputQueues>());

    // ★ signal_queues：Radius/PPPoE → OutputThread
    auto signal_queues = std::make_unique<SignalOutputQueues>();

    // ── OutputThread ──────────────────────────────────────
    // ★ 使用 OutputThreadConfig（独立结构体，非嵌套 Config）
    OutputThreadConfig out_cfg{};
    out_cfg.raw_dir         = cfg.raw_dir;
    out_cfg.collector_id    = cfg.collector_id;
    out_cfg.rotate_interval = cfg.rotate_interval;   // 默认60秒
    out_cfg.drain_batch     = 256;
    out_cfg.idle_sleep_us   = 500;

    auto output_thread = std::make_unique<OutputThread>(out_cfg);
    for (auto& wq : worker_out_queues)
        output_thread->registerWorkerQueues(wq.get());
    output_thread->registerSignalQueues(signal_queues.get()); // ★
    output_thread->start();
    spdlog::info("[OutputThread] started");

    // ── lcore 分配检查 ────────────────────────────────────
    LcoreAllocator lcore_alloc;
    uint32_t required_lcores = cfg.nb_rx_queues
                             + cfg.nb_workers
                             + 1; // RadiusThread
    if (lcore_alloc.remaining() < required_lcores) {
        spdlog::critical(
            "[Main] not enough lcores! need={} available={}. "
            "Check -l range in EAL args.",
            required_lcores, lcore_alloc.remaining());
        output_thread->stop();
        output_thread->join();
        ring_pool.destroyAll();
        dpdk.shutdown();
        rte_eal_cleanup();
        return 1;
    }

    // ── RadiusThread ──────────────────────────────────────
    // ★ 字段对齐最新 radius_thread.h：
    //   - 移除 file_mgr / ring_wait_warn_ms
    //   - signal_queues 移入 Config
    //   - 新增 lcore_id / req_timeout_us / purge_interval_us
    uint32_t radius_lcore = lcore_alloc.alloc("RadiusThread");

    RadiusThreadConfig rt_cfg{};
    rt_cfg.radius_ring       = radius_ring;
    rt_cfg.pppoe_ring        = pppoe_ring;
    rt_cfg.signal_queues     = signal_queues.get(); // ★ 移入Config
    rt_cfg.lcore_id          = radius_lcore;        // ★ 新增
    rt_cfg.burst_size        = 32;
    rt_cfg.req_timeout_us    = 5ULL * 1000000;      // ★ 新增 5秒
    rt_cfg.purge_interval_us = 1ULL * 1000000;      // ★ 新增 1秒

    auto radius_thread = std::make_unique<RadiusThread>(rt_cfg);
    rte_eal_remote_launch(RadiusThread::lcoreEntry,
                          radius_thread.get(), radius_lcore);
    GlobalStats::instance().registerThread(
        "radius", &radius_thread->stats());
    spdlog::info("[RadiusThread] launched on lcore {}",
                 radius_lcore);

    // ── WorkerThread（多个）──────────────────────────────
    // ★ 字段对齐最新 worker_thread.h：
    //   - bras_network → user_net
    //   - bras_netmask → user_mask
    //   - 新增 lcore_id / flow_timeout_us / onu_url_prefix
    std::vector<std::unique_ptr<WorkerThread>> worker_threads;
    std::vector<uint32_t> worker_lcore_ids;

    for (uint16_t w = 0; w < cfg.nb_workers; ++w) {
        uint32_t lcore_id = lcore_alloc.alloc(
            "WorkerThread#" + std::to_string(w));

        WorkerThreadConfig wt_cfg{};
        wt_cfg.ring            = worker_rings[w];
        wt_cfg.output_queues   = worker_out_queues[w].get();
        wt_cfg.worker_id       = w;
        wt_cfg.lcore_id        = lcore_id;           // ★ 新增
        wt_cfg.user_net        = cfg.bras_network;   // ★ 改名
        wt_cfg.user_mask       = cfg.bras_netmask;   // ★ 改名
        wt_cfg.flow_timeout_us = 120ULL * 1000000;   // ★ 新增
        strncpy(wt_cfg.onu_url_prefix,               // ★ 新增
                cfg.onu_url_prefix.c_str(), 63);

        auto wt = std::make_unique<WorkerThread>(wt_cfg);
        rte_eal_remote_launch(WorkerThread::lcoreEntry,
                              wt.get(), lcore_id);

        GlobalStats::instance().registerThread(
            "worker_" + std::to_string(w), &wt->stats());

        worker_lcore_ids.push_back(lcore_id);
        worker_threads.push_back(std::move(wt));

        spdlog::info("[WorkerThread#{}] launched on lcore {}",
                     w, lcore_id);
    }

    // ── RxThread（多个）──────────────────────────────────
    std::vector<std::unique_ptr<RxThread>> rx_threads;
    std::vector<uint32_t> rx_lcore_ids;

    for (uint16_t q = 0; q < cfg.nb_rx_queues; ++q) {
        uint32_t lcore_id = lcore_alloc.alloc(
            "RxThread#" + std::to_string(q));

        RxThreadConfig rx_cfg{};
        rx_cfg.port_id    = cfg.port_configs[0].port_id;
        rx_cfg.queue_id   = q;
        rx_cfg.lcore_id   = lcore_id;
        rx_cfg.dispatcher = dispatcher.get();
        rx_cfg.burst_size = BURST_SIZE;

        auto rx = std::make_unique<RxThread>(rx_cfg);
        rte_eal_remote_launch(RxThread::lcoreEntry,
                              rx.get(), lcore_id);

        GlobalStats::instance().registerThread(
            "rx_" + std::to_string(q), &rx->stats());

        rx_lcore_ids.push_back(lcore_id);
        rx_threads.push_back(std::move(rx));

        spdlog::info("[RxThread#{}] launched on lcore {} queue {}",
                     q, lcore_id, q);
    }

    // ── MonitorThread ─────────────────────────────────────
    MonitorThread::Config mon_cfg{};
    mon_cfg.report_interval_sec    = 10;
    mon_cfg.stall_check_sec        = 30;
    mon_cfg.drop_rate_warn_pct     = 1.0;
    mon_cfg.drop_rate_crit_pct     = 5.0;
    mon_cfg.queue_warn_level       = 0.8f;
    mon_cfg.enable_restart         = true;
    mon_cfg.min_rx_pps_for_stall   = 1000;

    auto monitor = std::make_unique<MonitorThread>(mon_cfg);
    for (size_t i = 0; i < rx_threads.size(); ++i)
        monitor->registerRx(rx_threads[i].get(), rx_lcore_ids[i]);
    for (size_t i = 0; i < worker_threads.size(); ++i)
        monitor->registerWorker(worker_threads[i].get(),
                                worker_lcore_ids[i]);
    monitor->registerRadius(radius_thread.get());
    monitor->registerOutput(output_thread.get());
    monitor->setDispatcher(dispatcher.get());
    monitor->start();
    spdlog::info("[MonitorThread] started");

    // ── 信号注册 ──────────────────────────────────────────
    signal(SIGINT,  sigHandler);
    signal(SIGTERM, sigHandler);

    spdlog::info("╔══════════════════════════════════════╗");
    spdlog::info("║  All threads running. Press Ctrl+C   ║");
    spdlog::info("║  to stop.                            ║");
    spdlog::info("╚══════════════════════════════════════╝");

    // ── 主循环：监控 lcore 意外退出 ───────────────────────
    while (!g_force_quit) {
        uint32_t lcore;
        RTE_LCORE_FOREACH_WORKER(lcore) {
            if (rte_eal_get_lcore_state(lcore) == FINISHED) {
                spdlog::error(
                    "[Main] lcore {} finished unexpectedly!",
                    lcore);
            }
        }
        std::this_thread::sleep_for(
            std::chrono::milliseconds(200));
    }

    // ════════════════════════════════════════════════════
    // 优雅关闭序列
    // ════════════════════════════════════════════════════
    spdlog::info("[Main] stopping all threads...");

    // ① 先停 Rx：不再入队新包
    for (auto& rx : rx_threads)
        rx->stop();
    for (uint32_t lcore : rx_lcore_ids)
        rte_eal_wait_lcore(lcore);
    spdlog::info("[Main] Rx threads stopped");

    // ② 等待 Worker ring 清空（最多5秒）
    {
        auto wait_start = std::chrono::steady_clock::now();
        bool all_empty  = false;
        while (!all_empty) {
            all_empty = true;
            for (auto* r : worker_rings) {
                if (rte_ring_count(r) > 0) {
                    all_empty = false;
                    break;
                }
            }
            if (!all_empty) {
                auto elapsed =
                    std::chrono::duration_cast<
                        std::chrono::seconds>(
                        std::chrono::steady_clock::now()
                        - wait_start).count();
                if (elapsed > 5) {
                    spdlog::warn(
                        "[Main] worker rings not empty "
                        "after 5s, forcing stop");
                    break;
                }
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(50));
            }
        }
        spdlog::info("[Main] worker rings drained");
    }

    // ③ 停 Worker
    for (auto& wt : worker_threads)
        wt->stop();
    for (uint32_t lcore : worker_lcore_ids)
        rte_eal_wait_lcore(lcore);
    spdlog::info("[Main] Worker threads stopped");

    // ④ 停 Radius
    radius_thread->stop();
    rte_eal_wait_lcore(radius_lcore);
    spdlog::info("[Main] Radius thread stopped");

    // ⑤ 等待 Radius/PPPoE ring 清空（最多2秒）
    {
        for (int retry = 0; retry < 100; ++retry) {
            if (rte_ring_count(radius_ring) == 0 &&
                rte_ring_count(pppoe_ring)  == 0)
                break;
            std::this_thread::sleep_for(
                std::chrono::milliseconds(20));
        }
    }

    // ⑥ 停 Output（flush 所有剩余记录）
    output_thread->stop();
    output_thread->join();
    spdlog::info("[Main] Output thread stopped. "
                 "tcp={} http={} onu={} radius={} pppoe={} "
                 "dns={} udp={}",
                 output_thread->writtenTcp(),
                 output_thread->writtenHttp(),
                 output_thread->writtenOnu(),
                 output_thread->writtenRadius(),
                 output_thread->writtenPppoe(),
                 output_thread->writtenDns(),
                 output_thread->writtenUdp());

    // ⑦ 停 Monitor
    monitor->stop();
    monitor->join();
    spdlog::info("[Main] Monitor thread stopped");

    // ── 资源清理 ──────────────────────────────────────────
    if (hw_flow)
        hw_flow->destroyAllRules();

    ring_pool.destroyAll();
    spdlog::info("[RingPool] all rings destroyed");

    dpdk.shutdown();
    spdlog::info("[DPDK] ports closed");

    rte_eal_cleanup();
    spdlog::info("[DPDK] EAL cleanup done");

    spdlog::info("╔══════════════════════════════════════╗");
    spdlog::info("║  Collector stopped cleanly.          ║");
    spdlog::info("╚══════════════════════════════════════╝");
    return 0;
}
