#include "radius_thread.h"

#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_byteorder.h>

#include <unistd.h>
#include <arpa/inet.h>
#include <cstring>
#include <spdlog/spdlog.h>

// ─────────────────────────────────────────────────────────
// 构造
// ─────────────────────────────────────────────────────────
RadiusThread::RadiusThread(const Config& cfg)
    : cfg_(cfg)
{
    if (!cfg_.radius_ring)
        throw std::runtime_error("RadiusThread: radius_ring is null");
    if (!cfg_.signal_queues)
        throw std::runtime_error("RadiusThread: signal_queues is null");
}

// ─────────────────────────────────────────────────────────
// DPDK lcore 入口
// ─────────────────────────────────────────────────────────
int RadiusThread::lcoreEntry(void* arg) {
    static_cast<RadiusThread*>(arg)->run();
    return 0;
}

// ─────────────────────────────────────────────────────────
// 从以太头解析 MAC，跳过 VLAN，返回 IP 层偏移
// ─────────────────────────────────────────────────────────
uint32_t RadiusThread::parseEthHeader(const uint8_t* data,
                                       uint32_t       pkt_len,
                                       uint64_t&      src_mac_out,
                                       uint64_t&      dst_mac_out)
{
    if (pkt_len < 14) return UINT32_MAX;

    const auto* eth =
        reinterpret_cast<const rte_ether_hdr*>(data);

    auto mac6to64 = [](const uint8_t* m) -> uint64_t {
        return ((uint64_t)m[0]<<40)|((uint64_t)m[1]<<32)|
               ((uint64_t)m[2]<<24)|((uint64_t)m[3]<<16)|
               ((uint64_t)m[4]<< 8)| (uint64_t)m[5];
    };
    src_mac_out = mac6to64(eth->src_addr.addr_bytes);
    dst_mac_out = mac6to64(eth->dst_addr.addr_bytes);

    uint16_t etype  = rte_be_to_cpu_16(eth->ether_type);
    uint32_t offset = sizeof(rte_ether_hdr);

    // 剥离 VLAN / QinQ
    while ((etype == 0x8100 || etype == 0x88A8) &&
           offset + 4 <= pkt_len)
    {
        etype = rte_be_to_cpu_16(
            *reinterpret_cast<const uint16_t*>(data+offset+2));
        offset += 4;
    }

    // 只处理 IPv4
    if (etype != 0x0800)       return UINT32_MAX;
    if (offset + 20 > pkt_len) return UINT32_MAX;
    return offset;
}

// ─────────────────────────────────────────────────────────
// 处理单个 Radius mbuf
// ─────────────────────────────────────────────────────────
void RadiusThread::processRadiusMbuf(
    struct rte_mbuf*         m,
    uint64_t                 ts_us,
    RadiusParser&            parser,
    RadiusSessionManager&    session_mgr,
    const std::function<void(const RadiusRecord&)>& on_complete)
{
    // 确保包内存连续
    if (!rte_pktmbuf_is_contiguous(m)) {
        if (rte_pktmbuf_linearize(m) != 0) {
            ++parse_errors_;
            return;
        }
    }

    const uint8_t* data    = rte_pktmbuf_mtod(m, const uint8_t*);
    uint32_t       pkt_len = rte_pktmbuf_pkt_len(m);

    // ── 以太层 ───────────────────────────────────────────
    uint64_t src_mac = 0, dst_mac = 0;
    uint32_t ip_offset = parseEthHeader(data, pkt_len,
                                         src_mac, dst_mac);
    if (ip_offset == UINT32_MAX) { ++parse_errors_; return; }

    // ── IP 层 ────────────────────────────────────────────
    const auto* ip =
        reinterpret_cast<const rte_ipv4_hdr*>(data + ip_offset);
    uint32_t ip_hlen = (ip->version_ihl & 0x0F) * 4;
    uint32_t src_ip  = ntohl(ip->src_addr);
    uint32_t dst_ip  = ntohl(ip->dst_addr);

    if (ip->next_proto_id != IPPROTO_UDP) {
        ++parse_errors_; return;
    }
    uint32_t udp_offset = ip_offset + ip_hlen;
    if (udp_offset + 8 > pkt_len) { ++parse_errors_; return; }

    // ── Radius payload（跳过UDP头8字节）─────────────────
    uint32_t radius_offset = udp_offset + 8;
    if (radius_offset >= pkt_len) { ++parse_errors_; return; }

    const uint8_t* radius_payload = data + radius_offset;
    uint32_t       radius_len     = pkt_len - radius_offset;

    // Radius 方向判断：
    //   请求包（NAS→Server）src_mac = BRAS MAC
    //   响应包（Server→NAS）dst_mac = BRAS MAC
    // 统一用 src_mac 作为 bras_mac（请求方向），
    // parser 内部根据 code 判断方向并修正
    uint64_t bras_mac = src_mac;

    RadiusRecord rec;
    if (!parser.parse(radius_payload, radius_len,
                      src_ip, dst_ip, bras_mac, ts_us, rec))
    {
        ++parse_errors_;
        return;
    }

    ++radius_parsed_;
    session_mgr.onPacket(rec, on_complete);
}

// ─────────────────────────────────────────────────────────
// 处理单个 PPPoE 信令 mbuf
// 只处理 PPPoE Discovery 阶段（PADI/PADO/PADR/PADS/PADT）
// EtherType = 0x8863
// ─────────────────────────────────────────────────────────
void RadiusThread::processPPPoEMbuf(struct rte_mbuf* m,
                                     uint64_t         ts_us)
{
    if (!rte_pktmbuf_is_contiguous(m)) {
        if (rte_pktmbuf_linearize(m) != 0) {
            ++parse_errors_; return;
        }
    }

    const uint8_t* data    = rte_pktmbuf_mtod(m, const uint8_t*);
    uint32_t       pkt_len = rte_pktmbuf_pkt_len(m);

    if (pkt_len < 14 + 6) { ++parse_errors_; return; }

    const auto* eth =
        reinterpret_cast<const rte_ether_hdr*>(data);

    auto mac6to64 = [](const uint8_t* mac) -> uint64_t {
        return ((uint64_t)mac[0]<<40)|((uint64_t)mac[1]<<32)|
               ((uint64_t)mac[2]<<24)|((uint64_t)mac[3]<<16)|
               ((uint64_t)mac[4]<< 8)| (uint64_t)mac[5];
    };

    uint16_t etype = rte_be_to_cpu_16(eth->ether_type);
    uint32_t offset = sizeof(rte_ether_hdr);

    // 剥离 VLAN
    while ((etype == 0x8100 || etype == 0x88A8) &&
           offset + 4 <= pkt_len)
    {
        etype = rte_be_to_cpu_16(
            *reinterpret_cast<const uint16_t*>(data+offset+2));
        offset += 4;
    }

    // 只处理 PPPoE Discovery（0x8863）
    if (etype != 0x8863) return;
    if (offset + 6 > pkt_len) { ++parse_errors_; return; }

    // PPPoE Discovery 头部：
    //   ver_type(1) + code(1) + session_id(2) + length(2)
    uint8_t  pppoe_code = data[offset + 1];
    uint16_t session_id = rte_be_to_cpu_16(
        *reinterpret_cast<const uint16_t*>(data + offset + 2));

    PPPoERecord rec{};
    rec.event_time = ts_us;
    rec.event_type = pppoe_code;
    rec.client_mac = mac6to64(eth->src_addr.addr_bytes);
    rec.server_mac = mac6to64(eth->dst_addr.addr_bytes);
    rec.session_id = session_id;

    // PPPoE Tags（offset+6 开始）
    uint32_t tag_offset = offset + 6;
    uint16_t pppoe_payload_len = rte_be_to_cpu_16(
        *reinterpret_cast<const uint16_t*>(data + offset + 4));
    uint32_t tag_end = offset + 6 + pppoe_payload_len;
    tag_end = std::min(tag_end, pkt_len);

    while (tag_offset + 4 <= tag_end) {
        uint16_t tag_type = rte_be_to_cpu_16(
            *reinterpret_cast<const uint16_t*>(data+tag_offset));
        uint16_t tag_len  = rte_be_to_cpu_16(
            *reinterpret_cast<const uint16_t*>(data+tag_offset+2));

        if (tag_offset + 4 + tag_len > tag_end) break;

        const uint8_t* tag_val = data + tag_offset + 4;

        switch (tag_type) {
        case 0x0101: // AC-Name
        {
            uint16_t copy = (uint16_t)std::min(
                (uint32_t)tag_len,
                (uint32_t)sizeof(rec.ac_name) - 1);
            memcpy(rec.ac_name, tag_val, copy);
            rec.ac_name[copy] = '\0';
            break;
        }
        case 0x0102: // Service-Name
        {
            uint16_t copy = (uint16_t)std::min(
                (uint32_t)tag_len,
                (uint32_t)sizeof(rec.service_name) - 1);
            memcpy(rec.service_name, tag_val, copy);
            rec.service_name[copy] = '\0';
            break;
        }
        default:
            break;
        }

        tag_offset += 4 + tag_len;
    }

    // 推送到输出队列
    if (!cfg_.signal_queues->pppoe_q.push(rec)) {
        stats_.drop_pkts.fetch_add(1,
            std::memory_order_relaxed);
    } else {
        ++pppoe_parsed_;
    }
}

// ─────────────────────────────────────────────────────────
// 根据 Radius 计费类型更新在线用户表
// ─────────────────────────────────────────────────────────
void RadiusThread::handleRadiusSession(const RadiusRecord& rec) {
    // 只处理 Acct-Request（code=4）
    if (rec.request_code != 4) return;
    if (rec.framed_ip == 0)    return;

    switch (rec.acct_status_type) {
    case 1: {
        // Accounting-Start：用户上线
        UserSession us{};
        strncpy(us.user_account, rec.user_name,
                sizeof(us.user_account) - 1);
        us.framed_ip   = rec.framed_ip;
        us.user_mac    = rec.calling_station_id_int;
        us.bras_mac    = rec.bras_mac;
        us.online_time = (uint64_t)(rec.start_time * 1e6);
        us.online      = true;

        RadiusSessionTable::instance().userOnline(
            rec.framed_ip, us);
        ++online_users_;

        spdlog::debug("[RadiusThread] user online: {} ip={}",
                      rec.user_name, rec.framed_ip);
        break;
    }
    case 2:
        // Accounting-Stop：用户下线
        RadiusSessionTable::instance().userOffline(rec.framed_ip);
        if (online_users_ > 0) --online_users_;

        spdlog::debug("[RadiusThread] user offline: {} ip={}",
                      rec.user_name, rec.framed_ip);
        break;

    case 3: {
        // Interim-Update：刷新在线时间
        UserSession us{};
        if (RadiusSessionTable::instance().lookup(
                rec.framed_ip, us))
        {
            us.online_time = (uint64_t)(rec.start_time * 1e6);
            RadiusSessionTable::instance().userOnline(
                rec.framed_ip, us);
        }
        break;
    }
    default:
        break;
    }
}

// ─────────────────────────────────────────────────────────
// 主循环
// ─────────────────────────────────────────────────────────
void RadiusThread::run() {
    state_.store(ThreadState::RUNNING, std::memory_order_relaxed);
    spdlog::info("[RadiusThread] started on lcore {}",
                 cfg_.lcore_id);

    RadiusParser         parser;
    RadiusSessionManager session_mgr(cfg_.req_timeout_us);

    static constexpr uint16_t BURST = 32;
    struct rte_mbuf* radius_mbufs[BURST];
    struct rte_mbuf* pppoe_mbufs [BURST];

    uint64_t last_purge_us = 0;
    uint64_t last_log_us   = 0;
    uint64_t last_pkt_us   = 0;
    uint32_t idle_count    = 0;

    static constexpr uint64_t LOG_INTERVAL_US =
        60ULL * 1000000; // 60秒打印一次

    // 配对完成回调：更新用户表 + 推送队列
    auto on_radius_complete = [this](const RadiusRecord& rec) {
        // 1. 更新在线用户表
        handleRadiusSession(rec);

        // 2. 推送到输出队列
        if (!cfg_.signal_queues->radius_q.push(rec)) {
            stats_.drop_pkts.fetch_add(1,
                std::memory_order_relaxed);
            spdlog::warn("[RadiusThread] radius_q full, "
                         "dropping record user={}",
                         rec.user_name);
        }
    };

    while (running_.load(std::memory_order_relaxed)) {
        bool had_work = false;

        // ── 消费 Radius 环 ────────────────────────────────
        uint16_t nb_radius = (uint16_t)rte_ring_dequeue_burst(
            cfg_.radius_ring,
            (void**)radius_mbufs,
            cfg_.burst_size,
            nullptr);

        if (nb_radius > 0) {
            for (uint16_t i = 0; i < nb_radius; ++i) {
                struct rte_mbuf* m = radius_mbufs[i];
                last_pkt_us = m->timestamp / 1000;

                processRadiusMbuf(m, last_pkt_us,
                                  parser, session_mgr,
                                  on_radius_complete);
                rte_pktmbuf_free(m);
            }
            stats_.rx_pkts.fetch_add(nb_radius,
                std::memory_order_relaxed);
            had_work = true;
        }

        // ── 消费 PPPoE 环 ─────────────────────────────────
        if (cfg_.pppoe_ring) {
            uint16_t nb_pppoe = (uint16_t)rte_ring_dequeue_burst(
                cfg_.pppoe_ring,
                (void**)pppoe_mbufs,
                cfg_.burst_size,
                nullptr);

            if (nb_pppoe > 0) {
                for (uint16_t i = 0; i < nb_pppoe; ++i) {
                    struct rte_mbuf* m = pppoe_mbufs[i];
                    uint64_t ts_us = m->timestamp / 1000;
                    processPPPoEMbuf(m, ts_us);
                    rte_pktmbuf_free(m);
                }
                stats_.rx_pkts.fetch_add(nb_pppoe,
                    std::memory_order_relaxed);
                had_work = true;
            }
        }

        // ── 定期清理超时未响应的 Radius 请求 ─────────────
        if (last_pkt_us > 0 &&
            last_pkt_us - last_purge_us >=
                cfg_.purge_interval_us)
        {
            session_mgr.purgeExpired(last_pkt_us,
                                     on_radius_complete);
            last_purge_us = last_pkt_us;
        }

        // ── 定期统计日志 ──────────────────────────────────
        if (last_pkt_us > 0 &&
            last_pkt_us - last_log_us > LOG_INTERVAL_US)
        {
            spdlog::info(
                "[RadiusThread] "
                "rx={} radius_parsed={} pppoe={} "
                "errors={} online_users={}",
                stats_.rx_pkts.load(),
                radius_parsed_, pppoe_parsed_,
                parse_errors_,  online_users_);
            last_log_us = last_pkt_us;
        }

        // ── 空转休眠 ──────────────────────────────────────
        if (!had_work) {
            ++idle_count;
            if      (idle_count < 1000)   rte_pause();
            else if (idle_count < 10000)  rte_delay_us_block(10);
            else                          usleep(100);
        } else {
            idle_count = 0;
        }
    }

    // ── 退出前：flush 剩余未匹配请求 ──────────────────────
    spdlog::info("[RadiusThread] flushing pending requests: {}",
                 session_mgr.pendingCount());
    session_mgr.purgeAll(on_radius_complete);

    state_.store(ThreadState::STOPPED, std::memory_order_relaxed);
    spdlog::info(
        "[RadiusThread] stopped. "
        "rx={} radius={} pppoe={} errors={} online={}",
        stats_.rx_pkts.load(),
        radius_parsed_, pppoe_parsed_,
        parse_errors_,  online_users_);
}
