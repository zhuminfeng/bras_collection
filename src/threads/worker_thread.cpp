#include "worker_thread.h"

#include <rte_ring.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_ether.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>

#include "../session/flow_table.h"
#include "../session/radius_session_table.h"
#include "../record/http_record.h"
#include "../record/record_types.h"
#include "../record/onu_record.h"
#include "../utils/time_utils.h"
#include <spdlog/spdlog.h>

// ─────────────────────────────────────────────────────────
// MurmurHash32（用于host_hash）
// ─────────────────────────────────────────────────────────
static uint32_t murmur32(const char* key, uint32_t len) {
    const uint32_t SEED = 0x9747b28c;
    const uint8_t* data = (const uint8_t*)key;
    uint32_t h = SEED ^ (len * 0xcc9e2d51);
    for (uint32_t i = 0; i + 4 <= len; i += 4) {
        uint32_t k; memcpy(&k, data + i, 4);
        k *= 0xcc9e2d51; k = (k<<15)|(k>>17); k *= 0x1b873593;
        h ^= k; h = (h<<13)|(h>>19); h = h*5 + 0xe6546b64;
    }
    uint32_t tail = 0;
    switch (len & 3) {
    case 3: tail |= (uint32_t)data[len-1] << 16; [[fallthrough]];
    case 2: tail |= (uint32_t)data[len-2] << 8;  [[fallthrough]];
    case 1: tail |= data[len-3];
        tail *= 0xcc9e2d51; tail=(tail<<15)|(tail>>17);
        tail *= 0x1b873593; h ^= tail;
    }
    h ^= len;
    h ^= h>>16; h *= 0x85ebca6b;
    h ^= h>>13; h *= 0xc2b2ae35;
    h ^= h>>16;
    return h;
}

// ─────────────────────────────────────────────────────────
// 跳过 VLAN/PPPoE，定位 IP 层
// ─────────────────────────────────────────────────────────
static uint32_t skipToIp(const uint8_t* raw, uint32_t pkt_len,
                          uint64_t& src_mac, uint64_t& dst_mac,
                          bool& is_pppoe)
{
    if (pkt_len < 14) return UINT32_MAX;
    const auto* eth = reinterpret_cast<const rte_ether_hdr*>(raw);

    auto mac6to64 = [](const uint8_t* m) -> uint64_t {
        return ((uint64_t)m[0]<<40)|((uint64_t)m[1]<<32)|
               ((uint64_t)m[2]<<24)|((uint64_t)m[3]<<16)|
               ((uint64_t)m[4]<< 8)| (uint64_t)m[5];
    };
    src_mac = mac6to64(eth->src_addr.addr_bytes);
    dst_mac = mac6to64(eth->dst_addr.addr_bytes);

    uint16_t etype = rte_be_to_cpu_16(eth->ether_type);
    uint32_t offset = sizeof(rte_ether_hdr);

    while ((etype == 0x8100 || etype == 0x88A8) &&
           offset + 4 <= pkt_len) {
        etype = rte_be_to_cpu_16(
            *reinterpret_cast<const uint16_t*>(raw+offset+2));
        offset += 4;
    }

    is_pppoe = false;
    if (etype == 0x8864 && offset + 8 <= pkt_len) {
        uint16_t ppp_proto = rte_be_to_cpu_16(
            *reinterpret_cast<const uint16_t*>(raw+offset+6));
        if (ppp_proto != 0x0021) return UINT32_MAX;
        offset += 8; etype = 0x0800; is_pppoe = true;
    }

    if (etype != 0x0800)   return UINT32_MAX;
    if (offset + 20 > pkt_len) return UINT32_MAX;
    return offset;
}

// ─────────────────────────────────────────────────────────
// 构建归一化 FlowKey（user 侧始终为 src）
// ─────────────────────────────────────────────────────────
static FlowKey makeKey(uint32_t src_ip, uint32_t dst_ip,
                        uint16_t src_port, uint16_t dst_port,
                        uint8_t proto, bool is_upstream)
{
    FlowKey k;
    if (is_upstream) {
        k.user_ip=src_ip; k.server_ip=dst_ip;
        k.user_port=src_port; k.server_port=dst_port;
    } else {
        k.user_ip=dst_ip; k.server_ip=src_ip;
        k.user_port=dst_port; k.server_port=src_port;
    }
    k.proto = proto;
    return k;
}

// ─────────────────────────────────────────────────────────
// 构造
// ─────────────────────────────────────────────────────────
WorkerThread::WorkerThread(const Config& cfg)
    : cfg_(cfg)
    , ring_(cfg.ring)
    , output_queues_(cfg.output_queues)
{
    if (!ring_)          throw std::runtime_error("WorkerThread: ring is null");
    if (!output_queues_) throw std::runtime_error("WorkerThread: output_queues is null");
}

// ─────────────────────────────────────────────────────────
// lcore 入口
// ─────────────────────────────────────────────────────────
int WorkerThread::lcoreEntry(void* arg) {
    static_cast<WorkerThread*>(arg)->run();
    return 0;
}

// ─────────────────────────────────────────────────────────
// 判断是否为 ONU 软探针上报
// ─────────────────────────────────────────────────────────
bool WorkerThread::isOnuReport(const FlowEntry& fe) const {
    const HttpSession& h = fe.http;

    // 必须是 POST
    if (h.req.method != HttpMethod::POST) return false;

    // URL 特征
    if (h.req.url[0]) {
        if (strstr(h.req.url, cfg_.onu_url_prefix) ||
            strstr(h.req.url, "/onu")              ||
            strstr(h.req.url, "/probe")            ||
            strstr(h.req.url, "/softprobe"))
            return true;
    }

    // Content-Type: application/json + ONU UA 特征
    if (h.req.content_type[0] &&
        strstr(h.req.content_type, "application/json"))
    {
        const char* ua = h.req.user_agent;
        if (strstr(ua, "SKYW") || strstr(ua, "FHTT") ||
            strstr(ua, "GWTT") || strstr(ua, "ZTEG") ||
            strstr(ua, "ONU-Agent") || strstr(ua, "softprobe"))
            return true;
    }

    return false;
}

// ─────────────────────────────────────────────────────────
// 统一流关闭出口
// ─────────────────────────────────────────────────────────
void WorkerThread::onTcpFlowClose(FlowEntry& fe, uint64_t now_us) {
    // ① 所有 TCP 流写 TCP 记录
    buildAndOutputTcpRecord(fe, now_us);

    // ② HTTP 流
    if (fe.is_http) {
        if (isOnuReport(fe)) {
            // ONU 软探针：写 ONU 记录，不写 HTTP 记录
            buildAndOutputOnuRecord(fe, now_us);
        } else {
            // 普通 HTTP：写 HTTP 记录
            buildAndOutputHttpRecord(fe, now_us);
        }
    }
}

// ─────────────────────────────────────────────────────────
// 处理单个 TCP 包
// ─────────────────────────────────────────────────────────
void WorkerThread::processTcpPacket(
    const uint8_t*      raw,
    uint32_t            pkt_len,
    const rte_ipv4_hdr* ip,
    uint32_t            ip_offset,
    uint64_t            ts_us,
    bool                is_upstream,
    uint64_t            src_mac,
    uint64_t            dst_mac,
    FlowTable&          flow_table)
{
    uint32_t ip_hlen = (ip->version_ihl & 0x0F) * 4;
    if (ip_offset + ip_hlen + sizeof(rte_tcp_hdr) > pkt_len) return;

    const auto* tcp = reinterpret_cast<const rte_tcp_hdr*>(
        raw + ip_offset + ip_hlen);
    uint32_t tcp_hlen      = ((tcp->data_off >> 4) & 0xF) * 4;
    uint32_t payload_offset= ip_offset + ip_hlen + tcp_hlen;
    uint32_t payload_len   = (payload_offset < pkt_len)
                           ? pkt_len - payload_offset : 0;

    uint32_t src_ip   = rte_be_to_cpu_32(ip->src_addr);
    uint32_t dst_ip   = rte_be_to_cpu_32(ip->dst_addr);
    uint16_t src_port = rte_be_to_cpu_16(tcp->src_port);
    uint16_t dst_port = rte_be_to_cpu_16(tcp->dst_port);
    uint32_t seq      = rte_be_to_cpu_32(tcp->sent_seq);
    uint32_t ack      = rte_be_to_cpu_32(tcp->recv_ack);
    uint8_t  flags    = tcp->tcp_flags;
    uint32_t ip_total = rte_be_to_cpu_16(ip->total_length);

    FlowKey key = makeKey(src_ip, dst_ip, src_port, dst_port,
                          IPPROTO_TCP, is_upstream);
    FlowEntry* fe = flow_table.getOrCreate(key, ts_us);
    if (!fe) return;

    // ── 首包初始化 ────────────────────────────────────────
    if (fe->user_mac == 0) {
        fe->user_mac = is_upstream ? src_mac : dst_mac;
        fe->bras_mac = is_upstream ? dst_mac : src_mac;
        fe->is_http  = isHttpPort(key.server_port);
    }

    // ── 关联 Radius 账号（首包查一次）────────────────────
    if (!fe->account_filled) {
        UserSession us{};
        if (RadiusSessionTable::instance().lookup(key.user_ip, us)) {
            memcpy(fe->user_account, us.user_account,
                   sizeof(fe->user_account));
            if (fe->user_mac == 0) fe->user_mac = us.user_mac;
            if (fe->bras_mac == 0) fe->bras_mac = us.bras_mac;
        }
        fe->account_filled = true;
    }

    TcpSession& s = fe->tcp;
    s.last_pkt_us = ts_us;

    // ── TCP 握手状态机 ────────────────────────────────────
    if (flags & RTE_TCP_SYN_FLAG) {
        if (!(flags & RTE_TCP_ACK_FLAG)) {
            s.syn_ts_us   = ts_us;
            s.hs_state    = HsState::SYN_SENT;
            s.user_launch = is_upstream;
            s.create_us   = ts_us;
            fe->create_us = ts_us;
        } else {
            if (s.hs_state == HsState::SYN_SENT) {
                s.synack_ts_us   = ts_us;
                s.hs_state       = HsState::ESTABLISHED;
                s.hs_user_rtt_ms = (uint16_t)(
                    (ts_us - s.syn_ts_us) / 1000);
            }
        }
    } else if ((flags & RTE_TCP_ACK_FLAG) &&
               s.synack_ts_us > 0 &&
               s.hs_state == HsState::ESTABLISHED)
    {
        s.hs_server_rtt_ms = (uint16_t)(
            (ts_us - s.synack_ts_us) / 1000);
        s.synack_ts_us = 0;
    }

    // ── RST ──────────────────────────────────────────────
    if (flags & RTE_TCP_RST_FLAG) {
        if (is_upstream) {
            if (s.hs_state == HsState::INIT ||
                s.hs_state == HsState::SYN_SENT)
                s.hs_state = HsState::USR_RST;
            s.sock_state = SockState::USR_RST;
        } else {
            if (s.hs_state == HsState::INIT ||
                s.hs_state == HsState::SYN_SENT)
                s.hs_state = HsState::SRV_RST;
            s.sock_state = SockState::SRV_RST;
        }
        s.is_closed = true;
        onTcpFlowClose(*fe, ts_us);
        fe->reset();
        return;
    }

    // ── FIN ──────────────────────────────────────────────
    if (flags & RTE_TCP_FIN_FLAG) {
        if (is_upstream) s.user_fin   = true;
        else             s.server_fin = true;
        if (s.user_fin && s.server_fin) {
            s.sock_state = SockState::SUCCESS;
            s.is_closed  = true;
        }
    }

    // ── 流量统计 ──────────────────────────────────────────
    if (is_upstream) {
        s.ul_bytes += ip_total; s.ul_pkts++;
        if (payload_len > 0) {
            s.ul_payload   += payload_len;
            s.eff_ul_bytes += ip_total;
            s.eff_ul_pkts++;
            if (s.first_data_us == 0) s.first_data_us = ts_us;
            s.last_data_us = ts_us;
        }
    } else {
        s.dl_bytes += ip_total; s.dl_pkts++;
        if (payload_len > 0) {
            s.dl_payload   += payload_len;
            s.eff_dl_bytes += ip_total;
            s.eff_dl_pkts++;
            if (s.first_data_us == 0) s.first_data_us = ts_us;
            s.last_data_us = ts_us;
        }
    }

    // ── RTT 计算 ──────────────────────────────────────────
    if (payload_len > 0) {
        if (is_upstream) s.server_rtt.onSend(seq+payload_len, ts_us);
        else             s.user_rtt  .onSend(seq+payload_len, ts_us);
    }
    if (flags & RTE_TCP_ACK_FLAG) {
        if (is_upstream) s.user_rtt  .onAck(ack, ts_us);
        else             s.server_rtt.onAck(ack, ts_us);
    }

    // ── 丢包/乱序检测 ─────────────────────────────────────
    if (payload_len > 0) {
        if (is_upstream) {
            s.ul_loss.onPacket(seq, payload_len, ts_us);
        } else {
            s.dl_loss.onPacket(seq, payload_len, ts_us);
            s.dl_repeat_pkts += s.dl_loss.repeat_count;
        }
    }

    // ── HTTP 解析（明文端口且有 payload）─────────────────
    if (fe->is_http && payload_len > 0) {
        const uint8_t* payload = raw + payload_offset;
        if (is_upstream)
            fe->http.onUpstreamData  (payload, payload_len, ts_us);
        else
            fe->http.onDownstreamData(payload, payload_len, ts_us);
    }

    // ── nDPI 协议识别 ──���──────────────────────────────────
    if (!fe->ndpi_state.detection_done) {
        ndpi_.processPacket(fe->ndpi_state,
                            raw + ip_offset,
                            pkt_len - ip_offset,
                            ts_us / 1000,
                            is_upstream);
        if (fe->ndpi_state.detection_done) {
            fe->traffic_type = ndpi_.getTrafficType(
                fe->ndpi_state.detected_proto);
            uint16_t app =
                fe->ndpi_state.detected_proto.app_protocol;
            if (app == NDPI_PROTOCOL_HTTP ||
                app == NDPI_PROTOCOL_HTTP_PROXY)
                fe->is_http = true;
        }
    }

    // ── 流已关闭：输出并释放 ──────────────────────────────
    if (s.is_closed) {
        onTcpFlowClose(*fe, ts_us);
        fe->reset();
        return;
    }

    fe->last_us = ts_us;
}

// ─────────────────────────────────────────────────────────
// 处理 UDP 包（DNS 识别 + UdpStream 统计）
// ─────────────────────────────────────────────────────────
void WorkerThread::processUdpPacket(
    const uint8_t*      raw,
    uint32_t            pkt_len,
    const rte_ipv4_hdr* ip,
    uint32_t            ip_offset,
    uint64_t            ts_us,
    bool                is_upstream)
{
    uint32_t ip_hlen = (ip->version_ihl & 0x0F) * 4;
    if (ip_offset + ip_hlen + 8 > pkt_len) return;

    const auto* udp = reinterpret_cast<const rte_udp_hdr*>(
        raw + ip_offset + ip_hlen);
    uint16_t src_port = rte_be_to_cpu_16(udp->src_port);
    uint16_t dst_port = rte_be_to_cpu_16(udp->dst_port);

    // DNS（端口53）
    if (dst_port == 53 || src_port == 53) {
        // dns_parser_.parse(...)  → output_queues_->dns_q.push(...)
        return;
    }

    // 其他 UDP（nDPI 识别后统计）
    // udp_session_table_.onPacket(...)
}

// ─────────────────────────────────────────────────────────
// 处理 ICMP 包（预留，目前不输出）
// ─────────────────────────────────────────────────────────
void WorkerThread::processIcmpPacket(
    const uint8_t* /*raw*/, uint32_t /*pkt_len*/,
    const rte_ipv4_hdr* /*ip*/, uint32_t /*ip_offset*/,
    uint64_t /*ts_us*/, bool /*is_upstream*/)
{
    // 预留：ICMP RTT 统计
}

// ─────────────────────────────────────────────────────────
// 组装 TcpSessionRecord
// ─────────────────────────────────────────────────────────
void WorkerThread::buildAndOutputTcpRecord(FlowEntry& fe,
                                            uint64_t   now_us)
{
    const TcpSession& s = fe.tcp;
    TcpSessionRecord  r;

    r.start_time      = (double)fe.create_us / 1e6;
    r.hour_round_time = TimeUtils::hourRoundTime(r.start_time);
    r.min_round_time  = TimeUtils::minRoundTime(r.start_time);

    if (fe.user_account[0])
        strncpy(r.user_account, fe.user_account, 255);
    r.user_mac_addr = fe.user_mac;
    r.bras_mac_addr = fe.bras_mac;
    r.user_ip       = fe.key.user_ip;
    r.server_ip     = fe.key.server_ip;

    if (fe.is_http && fe.http.req.host[0]) {
        strncpy(r.host_name, fe.http.req.host, 255);
        r.host_hash = murmur32(r.host_name,
                               (uint32_t)strlen(r.host_name));
    }

    r.user_port   = fe.key.user_port;
    r.server_port = fe.key.server_port;

    if (s.hs_state == HsState::SYN_SENT)
        const_cast<TcpSession&>(s).hs_state = HsState::SRV_NO_RSP;
    r.handshake_status = s.hsStatusDcs();
    r.socket_status    = s.sockStatusDcs();
    r.traffic_type     = fe.traffic_type;
    r.duration         = s.durationMs();

    r.ul_traffic = s.ul_bytes;
    r.dl_traffic = s.dl_bytes;

    r.user_rtt_count    = s.user_rtt.count;
    r.user_rtt_sum      = (uint32_t)s.user_rtt.sum_ms;
    r.server_rtt_count  = (uint16_t)std::min(
        s.server_rtt.count, (uint32_t)65535);
    r.server_rtt_sum    = (uint32_t)s.server_rtt.sum_ms;
    r.user_jitter_sum   = (uint32_t)s.user_rtt.jitter_sum_ms;
    r.server_jitter_sum = (uint32_t)s.server_rtt.jitter_sum_ms;

    r.server_loss = s.ul_loss.loss_count;
    r.user_loss   = s.dl_loss.loss_count;
    r.ul_packets  = s.ul_pkts;
    r.dl_packets  = s.dl_pkts;

    r.user_launch       = s.user_launch ? 1 : 0;
    r.dl_repeat_packets = s.dl_repeat_pkts;
    r.hs_user_rtt       = s.hs_user_rtt_ms;
    r.hs_server_rtt     = s.hs_server_rtt_ms;

    r.eff_duration   = s.effDurationMs();
    r.eff_ul_traffic = s.eff_ul_bytes;
    r.eff_dl_traffic = s.eff_dl_bytes;
    r.eff_ul_packets = s.eff_ul_pkts;
    r.eff_dl_packets = s.eff_dl_pkts;

    r.uplink_disorder_cnt   = s.ul_loss.disorder_count;
    r.downlink_disorder_cnt = s.dl_loss.disorder_count;

    if (!output_queues_->tcp_q.push(r)) {
        stats_.drop_pkts.fetch_add(1, std::memory_order_relaxed);
    } else {
        stats_.tcp_sessions.fetch_add(1, std::memory_order_relaxed);
    }
}

// ───────────────────────────────────────────────���─────────
// 组装 HttpRecord
// ─────────────────────────────────────────────────────────
void WorkerThread::buildAndOutputHttpRecord(FlowEntry& fe,
                                             uint64_t   now_us)
{
    if (!fe.is_http) return;

    HttpRecord         r;
    const TcpSession&  s = fe.tcp;
    const HttpSession& h = fe.http;

    r.start_time      = (double)fe.create_us / 1e6;
    r.hour_round_time = TimeUtils::hourRoundTime(r.start_time);
    r.min_round_time  = TimeUtils::minRoundTime(r.start_time);

    if (fe.user_account[0])
        strncpy(r.user_account, fe.user_account, 255);
    r.user_mac_addr = fe.user_mac;
    r.bras_mac_addr = fe.bras_mac;
    r.user_ip       = fe.key.user_ip;
    r.server_ip     = fe.key.server_ip;
    r.user_port     = fe.key.user_port;
    r.server_port   = fe.key.server_port;

    r.request_type = h.req.method;
    r.status_code  = h.rsp.status_code;

    if (h.req.host[0]) {
        strncpy(r.host_name, h.req.host, 255);
        r.host_hash = murmur32(h.req.host,
                               (uint32_t)strlen(h.req.host));
    }
    if (h.req.url[0])
        strncpy(r.url,                 h.req.url,          767);
    if (h.req.user_agent[0])
        strncpy(r.user_agent,          h.req.user_agent,   255);
    if (h.req.content_type[0])
        strncpy(r.client_content_type, h.req.content_type, 255);
    if (h.rsp.content_type[0])
        strncpy(r.server_content_type, h.rsp.content_type, 255);

    r.response_interval = h.response_interval_ms;

    if (h.req.user_agent[0]) {
        CpeInfo cpe = cpe_det_.detect(h.req.user_agent);
        strncpy(r.cpe_model,   cpe.model,   255);
        strncpy(r.cpe_version, cpe.version,  31);
    }

    if (s.hs_state == HsState::SYN_SENT)
        const_cast<TcpSession&>(s).hs_state = HsState::SRV_NO_RSP;
    r.handshake_status = s.hsStatusDcs();
    r.socket_status    = s.sockStatusDcs();
    r.traffic_type     = fe.traffic_type;
    r.duration         = s.durationMs();
    r.user_launch      = s.user_launch ? 1 : 0;
    r.hs_user_rtt      = s.hs_user_rtt_ms;
    r.hs_server_rtt    = s.hs_server_rtt_ms;

    r.ul_traffic      = s.ul_bytes;
    r.dl_traffic      = s.dl_bytes;
    r.http_ul_payload = s.ul_payload;
    r.http_dl_payload = s.dl_payload;
    r.ul_packets      = s.ul_pkts;
    r.dl_packets      = s.dl_pkts;

    r.eff_duration   = s.effDurationMs();
    r.eff_ul_traffic = s.eff_ul_bytes;
    r.eff_dl_traffic = s.eff_dl_bytes;
    r.eff_ul_packets = s.eff_ul_pkts;
    r.eff_dl_packets = s.eff_dl_pkts;

    r.server_rtt_count  = (uint16_t)std::min(
        s.server_rtt.count, (uint32_t)65535);
    r.server_rtt_sum    = (uint32_t)s.server_rtt.sum_ms;
    r.user_rtt_count    = s.user_rtt.count;
    r.user_rtt_sum      = (uint32_t)s.user_rtt.sum_ms;
    r.user_jitter_sum   = (uint32_t)s.user_rtt.jitter_sum_ms;
    r.server_jitter_sum = (uint32_t)s.server_rtt.jitter_sum_ms;

    r.server_loss       = s.ul_loss.loss_count;
    r.user_loss         = s.dl_loss.loss_count;
    r.dl_repeat_packets = s.dl_repeat_pkts;

    r.uplink_disorder_cnt   = s.ul_loss.disorder_count;
    r.downlink_disorder_cnt = s.dl_loss.disorder_count;

    if (fe.ndpi_state.detection_done) {
        std::string proto_name =
            ndpi_.getProtoName(fe.ndpi_state.detected_proto);
        strncpy(r.second_user_agent, proto_name.c_str(), 63);
    }

    if (!output_queues_->http_q.push(r)) {
        stats_.drop_pkts.fetch_add(1, std::memory_order_relaxed);
    } else {
        stats_.http_records.fetch_add(1, std::memory_order_relaxed);
    }
}

// ─────────────────────────────────────────────────────────
// 组装 OnuRecord（ONU 软探针上报）
// ─────────────────────────────────────────────────────────
void WorkerThread::buildAndOutputOnuRecord(FlowEntry& fe,
                                            uint64_t   now_us)
{
    if (!fe.is_http) return;
    if (fe.http.req.body_len == 0) return;

    OnuRecord onu_rec;
    if (!onu_parser_.parseJson(
            (const uint8_t*)fe.http.req.body,
            fe.http.req.body_len,
            fe.create_us,
            onu_rec))
    {
        stats_.drop_pkts.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    // 补充从 Radius 表获取的用户账号
    if (onu_rec.user_account[0] == '\0' &&
        fe.user_account[0] != '\0')
    {
        strncpy(onu_rec.user_account, fe.user_account, 255);
    }

    // 补充 user_mac（如果 JSON 中没有）
    if (onu_rec.user_mac_addr == 0 && fe.user_mac != 0)
        onu_rec.user_mac_addr = fe.user_mac;

    if (!output_queues_->onu_q.push(onu_rec)) {
        stats_.drop_pkts.fetch_add(1, std::memory_order_relaxed);
    } else {
        stats_.onu_records.fetch_add(1, std::memory_order_relaxed);
    }
}

// ─────────────────────────────────────────────────────────
// 主循环
// ─────────────────────────────────────────────────────────
void WorkerThread::run() {
    state_.store(ThreadState::RUNNING, std::memory_order_relaxed);
    spdlog::info("[WorkerThread#{}] started on lcore {}",
                 cfg_.worker_id, cfg_.lcore_id);

    static constexpr uint16_t BURST          = 64;
    static constexpr uint64_t PURGE_INTERVAL = 5ULL * 1000000;

    struct rte_mbuf* mbufs[BURST];
    FlowTable        flow_table(1 << 20);   // 1M 槽位
    uint64_t         last_purge_us = 0;
    uint64_t         last_pkt_us   = 0;

    while (running_.load(std::memory_order_relaxed)) {
        uint16_t nb = (uint16_t)rte_ring_dequeue_burst(
            ring_, (void**)mbufs, BURST, nullptr);

        if (nb == 0) { rte_pause(); continue; }

        for (uint16_t i = 0; i < nb; ++i) {
            // 预取下一个包的数据
            if (i + 1 < nb)
                rte_prefetch0(
                    rte_pktmbuf_mtod(mbufs[i+1], void*));

            struct rte_mbuf* m = mbufs[i];
            const uint8_t* raw = rte_pktmbuf_mtod(m, const uint8_t*);
            uint32_t pkt_len   = rte_pktmbuf_pkt_len(m);
            uint64_t ts_us     = m->timestamp / 1000;
            last_pkt_us        = ts_us;

            // ── 以太层解析 ───────────────────────────────
            uint64_t src_mac = 0, dst_mac = 0;
            bool     is_pppoe = false;
            uint32_t ip_offset = skipToIp(raw, pkt_len,
                                           src_mac, dst_mac,
                                           is_pppoe);
            if (ip_offset == UINT32_MAX) {
                rte_pktmbuf_free(m); continue;
            }

            // ── 硬件校验和错误丢弃 ───────────────────────
            if (m->ol_flags & RTE_MBUF_F_RX_IP_CKSUM_BAD ||
                m->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_BAD) {
                rte_pktmbuf_free(m); continue;
            }

            const auto* ip =
                reinterpret_cast<const rte_ipv4_hdr*>(
                    raw + ip_offset);
            uint32_t src_ip  = rte_be_to_cpu_32(ip->src_addr);
            bool is_upstream = isUserIp(src_ip);

            switch (ip->next_proto_id) {
            case IPPROTO_TCP:
                processTcpPacket(raw, pkt_len, ip, ip_offset,
                                 ts_us, is_upstream,
                                 src_mac, dst_mac, flow_table);
                break;
            case IPPROTO_UDP:
                processUdpPacket(raw, pkt_len, ip, ip_offset,
                                 ts_us, is_upstream);
                break;
            case IPPROTO_ICMP:
                processIcmpPacket(raw, pkt_len, ip, ip_offset,
                                  ts_us, is_upstream);
                break;
            default: break;
            }

            rte_pktmbuf_free(m);
            stats_.rx_pkts.fetch_add(1, std::memory_order_relaxed);
        }

        // ── 定期清理超时流 ────────────────────────────────
        if (last_pkt_us - last_purge_us > PURGE_INTERVAL) {
            flow_table.purgeExpired(
                last_pkt_us,
                cfg_.flow_timeout_us,
                [this](FlowEntry& fe) {
                    if (fe.tcp.hs_state == HsState::SYN_SENT)
                        fe.tcp.hs_state = HsState::SRV_NO_RSP;
                    if (fe.tcp.sock_state == SockState::ACTIVE)
                        fe.tcp.sock_state = SockState::EXCEPTION;
                    onTcpFlowClose(fe, fe.tcp.last_pkt_us);
                });
            last_purge_us = last_pkt_us;
        }
    }

    // ── 退出：flush 所有未关闭流 ──────────────────────────
    flow_table.purgeAll([this](FlowEntry& fe) {
        onTcpFlowClose(fe, fe.tcp.last_pkt_us);
    });

    state_.store(ThreadState::STOPPED, std::memory_order_relaxed);
    spdlog::info("[WorkerThread#{}] stopped. rx={} tcp={} http={} onu={}",
                 cfg_.worker_id,
                 stats_.rx_pkts.load(),
                 stats_.tcp_sessions.load(),
                 stats_.http_records.load(),
                 stats_.onu_records.load());
}
