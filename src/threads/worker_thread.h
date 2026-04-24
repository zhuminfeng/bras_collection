#pragma once

#include <rte_ring.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_ether.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <functional>

#include "../../include/common.h"
#include "../utils/stats.h"
#include "../session/flow_table.h"
#include "../session/tcp_session.h"
#include "../parser/ndpi_analyzer.h"
#include "../parser/cpe_detector.h"
#include "../parser/onu_parser.h"
#include "../record/http_record.h"
#include "../record/record_types.h"
#include "../record/onu_record.h"
#include "../utils/lock_free_queue.h"

// 前向声明
class RawFileManager;

// ─────────────────────────────────────────────────────────
// Worker 输出队列（WorkerThread → OutputThread）
// ─────────────────────────────────────────────────────────
struct WorkerOutputQueues {
    LockFreeQueue<HttpRecord>        http_q{4096};
    LockFreeQueue<TcpSessionRecord>  tcp_q {4096};
    LockFreeQueue<OnuRecord>         onu_q {1024};
    LockFreeQueue<DnsRecord>         dns_q {4096};
    LockFreeQueue<UdpStreamRecord>   udp_q {4096};

    WorkerOutputQueues()  = default;
    // NonCopyable
    WorkerOutputQueues(const WorkerOutputQueues&)            = delete;
    WorkerOutputQueues& operator=(const WorkerOutputQueues&) = delete;
};

// ─────────────────────────────────────────────────────────
// WorkerThread 配置
// ─────────────────────────────────────────────────────────
struct WorkerThreadConfig {
    struct rte_ring*      ring              = nullptr;
    WorkerOutputQueues*   output_queues     = nullptr;
    uint16_t              worker_id         = 0;
    uint32_t              lcore_id          = 0;

    // 用户网段（用于判断上下行方向）
    uint32_t              user_net          = 0;   // 主机序
    uint32_t              user_mask         = 0;   // 主机序

    // 流超时
    uint64_t              flow_timeout_us   = 120ULL * 1000000;

    // ONU 上报 URL 前缀（可配置）
    char                  onu_url_prefix[64]= "/report";
};

// ─────────────────────────────────────────────────────────
// WorkerThread
//
// 职责：
//   1. 从 rte_ring 消费 mbuf
//   2. 解析 Ethernet/IP/TCP/UDP
//   3. 维护 FlowTable（TCP流状态机）
//   4. 解析 HTTP（明文）/ ONU 软探针
//   5. nDPI 协议识别
//   6. 流关闭时序列化输出到队列
//   7. 定期清理超时流
//
// 线程模型：每个 WorkerThread 绑定一个 DPDK lcore，单线程
// ─────────────────────────────────────────────────────────
class WorkerThread : NonCopyable {
public:
    // WorkerThread::Config 即 WorkerThreadConfig 的别名
    using Config = WorkerThreadConfig;

    explicit WorkerThread(const Config& cfg);
    ~WorkerThread() = default;

    // ── DPDK lcore 入口 ───────────────────────────────────
    static int lcoreEntry(void* arg);

    // ── 生命周期控制 ─────────────────────────────────────
    void stop() {
        running_.store(false, std::memory_order_relaxed);
    }

    bool isRunning() const {
        return state_.load(std::memory_order_relaxed)
               == ThreadState::RUNNING;
    }

    // ── 统计 ─────────────────────────────────────────────
    ThreadStats&       stats()       { return stats_; }
    const ThreadStats& stats() const { return stats_; }

    uint16_t workerId() const { return cfg_.worker_id; }
    uint32_t lcoreId()  const { return cfg_.lcore_id;  }

private:
    // ── 主循环 ───────────────────────────────────────────
    void run();

    // ── 包处理 ───────────────────────────────────────────
    void processTcpPacket(const uint8_t*      raw,
                          uint32_t            pkt_len,
                          const rte_ipv4_hdr* ip,
                          uint32_t            ip_offset,
                          uint64_t            ts_us,
                          bool                is_upstream,
                          uint64_t            src_mac,
                          uint64_t            dst_mac,
                          FlowTable&          flow_table);

    void processUdpPacket(const uint8_t*      raw,
                          uint32_t            pkt_len,
                          const rte_ipv4_hdr* ip,
                          uint32_t            ip_offset,
                          uint64_t            ts_us,
                          bool                is_upstream);

    void processIcmpPacket(const uint8_t*      raw,
                           uint32_t            pkt_len,
                           const rte_ipv4_hdr* ip,
                           uint32_t            ip_offset,
                           uint64_t            ts_us,
                           bool                is_upstream);

    // ── 流关闭统一出口 ────────────────────────────────────
    void onTcpFlowClose(FlowEntry& fe, uint64_t now_us);

    // ── 输出记录构建 ─────────────────────────────────────
    void buildAndOutputTcpRecord (FlowEntry& fe, uint64_t now_us);
    void buildAndOutputHttpRecord(FlowEntry& fe, uint64_t now_us);
    void buildAndOutputOnuRecord (FlowEntry& fe, uint64_t now_us);

    // ── 辅助判断 ─────────────────────────────────────────
    // 判断 IP 是否属于用户网段（上行方向）
    bool isUserIp(uint32_t ip) const {
        return (ip & cfg_.user_mask) ==
               (cfg_.user_net & cfg_.user_mask);
    }

    // 判断端口是否可能是 HTTP（明文）
    static bool isHttpPort(uint16_t port) {
        return port == 80   || port == 8080 ||
               port == 8000 || port == 8888 ||
               port == 3128;
    }

    // 判断是否为 ONU 软探针上报
    bool isOnuReport(const FlowEntry& fe) const;

    // ── 成员变量 ─────────────────────────────────────────
    Config                     cfg_;
    struct rte_ring*           ring_;
    WorkerOutputQueues*        output_queues_;

    std::atomic<bool>          running_{true};
    std::atomic<ThreadState>   state_{ThreadState::IDLE};

    // 统计
    ThreadStats                stats_;

    // 协议分析器（每个Worker独立实例，无锁）
    NdpiAnalyzer               ndpi_;
    CpeDetector                cpe_det_;
    OnuParser                  onu_parser_;
};
