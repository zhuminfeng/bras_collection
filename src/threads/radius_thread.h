#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <stdexcept>

#include "../../include/common.h"
#include "../utils/stats.h"
#include "signal_queues.h"
#include "../parser/radius_parser.h"
#include "../session/radius_session_manager.h"
#include "../session/radius_session_table.h"

// 前向声明（避免包含 DPDK 头污染）
struct rte_ring;
struct rte_mbuf;

// ─────────────────────────────────────────────────────────
// RadiusThread 配置
// ─────────────────────────────────────────────────────────
struct RadiusThreadConfig {
    struct rte_ring*    radius_ring    = nullptr; // Radius UDP 包环
    struct rte_ring*    pppoe_ring     = nullptr; // PPPoE 信令包环（可为 null）
    SignalOutputQueues* signal_queues  = nullptr; // 输出队列
    uint32_t            lcore_id       = 0;
    uint16_t            burst_size     = 32;

    // 未匹配请求超时（微秒，默认5秒）
    uint64_t            req_timeout_us = 5ULL * 1000000;

    // 定期清理超时请求的间隔（微秒，默认1秒）
    uint64_t            purge_interval_us = 1ULL * 1000000;
};

// ─────────────────────────────────────────────────────────
// RadiusThread
//
// 职责：
//   1. 从 radius_ring 消费 Radius UDP mbuf
//   2. 解析 Radius 协议（AVP / VSA）
//   3. 请求/响应配对（RadiusSessionManager）
//   4. 配对完成后：
//      a. 更新在线用户表（RadiusSessionTable）
//      b. 推送 RadiusRecord 到 signal_queues->radius_q
//   5. 从 pppoe_ring 消费 PPPoE 信令 mbuf
//   6. 推送 PPPoERecord 到 signal_queues->pppoe_q
//   7. 定期清理超时未响应的 Radius 请求
//
// 线程模型：
//   绑定单个 DPDK lcore，单线程，无锁
// ─────────────────────────────────────────────────────────
class RadiusThread : NonCopyable {
public:
    using Config = RadiusThreadConfig;

    explicit RadiusThread(const Config& cfg);
    ~RadiusThread() = default;

    // DPDK lcore 入口
    static int lcoreEntry(void* arg);

    // 停止主循环
    void stop() {
        running_.store(false, std::memory_order_relaxed);
    }

    bool isRunning() const {
        return state_.load(std::memory_order_relaxed)
               == ThreadState::RUNNING;
    }

    // 统计
    const ThreadStats& stats() const { return stats_; }
    uint64_t radiusParsed() const { return radius_parsed_; }
    uint64_t pppoeParsed()  const { return pppoe_parsed_;  }
    uint64_t parseErrors()  const { return parse_errors_;  }
    uint64_t onlineUsers()  const { return online_users_;  }

private:
    // 主循环
    void run();

    // 处理单个 Radius mbuf
    void processRadiusMbuf(
        struct rte_mbuf*         m,
        uint64_t                 ts_us,
        RadiusParser&            parser,
        RadiusSessionManager&    session_mgr,
        const std::function<void(const RadiusRecord&)>& on_complete);

    // 处理单个 PPPoE mbuf
    void processPPPoEMbuf(struct rte_mbuf* m, uint64_t ts_us);

    // 根据 Radius 计费类型更新在线用户表
    void handleRadiusSession(const RadiusRecord& rec);

    // 从 mbuf 提取以太层信息，返回 IP 层偏移，失败返回 UINT32_MAX
    static uint32_t parseEthHeader(const uint8_t* data,
                                    uint32_t       pkt_len,
                                    uint64_t&      src_mac_out,
                                    uint64_t&      dst_mac_out);

    // 配置与状态
    Config                   cfg_;
    std::atomic<bool>        running_{true};
    std::atomic<ThreadState> state_{ThreadState::IDLE};

    // 统计
    ThreadStats  stats_;
    uint64_t     radius_parsed_ = 0;
    uint64_t     pppoe_parsed_  = 0;
    uint64_t     parse_errors_  = 0;
    uint64_t     online_users_  = 0;
};
