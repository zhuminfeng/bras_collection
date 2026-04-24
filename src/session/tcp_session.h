#pragma once
#include <cstdint>
#include <cstring>
#include <algorithm>

// ─────────────────────────────────────────────────────────
// 握手状态枚举
// DCS字段 handshake_status 映射：
//   0=成功  1=服务器无响应  2=用户侧无响应
//   3=用户侧复位  4=服务器复位  5=解码异常  6=初始
// ─────────────────────────────────────────────────────────
enum class HsState : uint8_t {
    INIT         = 6,   // 初始（未收到SYN）
    SYN_SENT     = 1,   // 发出SYN，等SYN-ACK（映射→服务器无响应）
    ESTABLISHED  = 0,   // 握手成功
    SRV_NO_RSP   = 1,   // 服务器无响应
    USR_NO_RSP   = 2,   // 用户侧无响应
    USR_RST      = 3,   // 用户侧复位
    SRV_RST      = 4,   // 服务器复位
    EXCEPTION    = 5,   // 解码异常
};

// ─────────────────────────────────────────────────────────
// Socket状态枚举
// DCS字段 socket_status 映射（同上）
// ─────────────────────────────────────────────────────────
enum class SockState : uint8_t {
    INIT      = 6,
    ACTIVE    = 0,   // 会话进行中（最终映射为成功）
    SUCCESS   = 0,   // 正常FIN关闭
    SRV_NO_RSP= 1,
    USR_NO_RSP= 2,
    USR_RST   = 3,
    SRV_RST   = 4,
    EXCEPTION = 5,
};

// ─────────────────────────────────────────────────────────
// RTT追踪器
//
// 原理：
//   发包方调用 onSend(seq_end, ts)  记录 "等待ACK的seq→时间"
//   对端ACK到来调用 onAck(ack, ts)  计算 RTT = now - send_ts
//
// 使用循环缓冲区记录最近N个未ACK的seq，
// 避免大量map/unordered_map的内存开销
// ─────────────────────────────────────────────────────────
struct RttTracker {
    static constexpr uint8_t  CAP = 16; // 记录最近16个未ACK数据包

    struct Entry {
        uint32_t seq_end  = 0;    // 数据包的 seq + payload_len
        uint64_t send_us  = 0;    // 发送时间（微秒）
        bool     valid    = false;
    };

    Entry    entries[CAP];
    uint8_t  write_idx   = 0;

    // 统计（单位：ms，累积值）
    uint64_t sum_ms       = 0;
    uint64_t jitter_sum_ms= 0;
    uint32_t count        = 0;
    uint64_t last_rtt_ms  = 0;

    // 发包时记录 seq_end → 时间
    void onSend(uint32_t seq_end, uint64_t ts_us) {
        Entry& e   = entries[write_idx % CAP];
        e.seq_end  = seq_end;
        e.send_us  = ts_us;
        e.valid    = true;
        ++write_idx;
    }

    // ACK到来：查找对应entry计算RTT
    void onAck(uint32_t ack, uint64_t ts_us) {
        for (auto& e : entries) {
            if (!e.valid) continue;
            // ack >= seq_end 表示该数据包已被确认
            // 使用有符号差避免序号回绕
            int32_t diff = (int32_t)(ack - e.seq_end);
            if (diff >= 0) {
                uint64_t rtt_us = (ts_us > e.send_us)
                                ? ts_us - e.send_us : 0;
                uint64_t rtt_ms = rtt_us / 1000;

                // 抖动 = |本次RTT - 上次RTT|
                if (count > 0) {
                    uint64_t jitter = (rtt_ms > last_rtt_ms)
                                    ? rtt_ms - last_rtt_ms
                                    : last_rtt_ms - rtt_ms;
                    jitter_sum_ms += jitter;
                }

                sum_ms    += rtt_ms;
                last_rtt_ms= rtt_ms;
                ++count;
                e.valid = false;  // 标记为已处理
                return;
            }
        }
    }

    // 平均RTT（ms），避免除零
    uint32_t avgMs() const {
        return count > 0 ? (uint32_t)(sum_ms / count) : 0;
    }

    void reset() {
        memset(this, 0, sizeof(*this));
    }
};

// ─────────────────────────────────────────────────────────
// 丢包/乱序检测器
//
// 原理：滑动窗口检测
//   每个包到来时，检查 seq 是否是期望的下一个seq
//   若seq < expected → 乱序或重复
//   若seq > expected → 有丢包（中间有间隔）
// ─────────────────────────────────────────────────────────
struct LossDetector {
    uint32_t  expected_seq   = 0;     // 期望的下一个seq
    bool      initialized    = false;

    // 统计
    uint32_t  loss_count     = 0;     // 丢包数（估算）
    uint32_t  disorder_count = 0;     // 乱序次数
    uint32_t  repeat_count   = 0;     // 本次onPacket检测到的重复数

    // 每个有payload的包调用一次
    void onPacket(uint32_t seq, uint32_t payload_len,
                  uint64_t /*ts_us*/) {
        repeat_count = 0;

        if (!initialized) {
            expected_seq = seq + payload_len;
            initialized  = true;
            return;
        }

        int32_t diff = (int32_t)(seq - expected_seq);

        if (diff == 0) {
            // 正常：按序到达
            expected_seq = seq + payload_len;

        } else if (diff > 0) {
            // seq > expected：中间有丢包
            // 估算丢包数：跳过的字节数 / 平均包大小(估算1400字节)
            uint32_t gap_bytes = (uint32_t)diff;
            uint32_t estimated = std::max(1u, gap_bytes / 1400u);
            loss_count   += estimated;
            expected_seq  = seq + payload_len;

        } else {
            // seq < expected：乱序或重复包
            // diff < 0 表示包的seq比期望的小
            int32_t end_diff = (int32_t)((seq + payload_len)
                                         - expected_seq);
            if (end_diff <= 0) {
                // 整个包在已收到范围内：重复包
                ++repeat_count;
            } else {
                // 部分重叠：乱序
                ++disorder_count;
                expected_seq = seq + payload_len;
            }
        }
    }

    void reset() {
        memset(this, 0, sizeof(*this));
    }
};

// ─────────────────────────────────────────────────────────
// TcpSession：一条TCP流的完整会话状态
// ─────────────────────────────────────────────────────────
struct TcpSession {

    // ── 时间戳 ────────────────────────────────────────────
    uint64_t  create_us      = 0;   // 流创建时间（首个SYN）
    uint64_t  last_pkt_us    = 0;   // 最后一个包时间
    uint64_t  first_data_us  = 0;   // 第一个有payload包的时间
    uint64_t  last_data_us   = 0;   // 最后一个有payload包的时间

    // ── 握手时间戳（计算握手RTT）─────────────────────────
    uint64_t  syn_ts_us      = 0;   // SYN发出时间
    uint64_t  synack_ts_us   = 0;   // SYN-ACK到达时间（用于计算server_rtt）

    // ── 握手RTT（毫秒）───────────────────────────────────
    uint16_t  hs_user_rtt_ms   = 0; // SYN → SYN-ACK（用户侧感知）
    uint16_t  hs_server_rtt_ms = 0; // SYN-ACK → ACK（服务器侧感知）

    // ── 状态机 ────────────────────────────────────────────
    HsState   hs_state    = HsState::INIT;
    SockState sock_state  = SockState::INIT;
    bool      is_closed   = false;
    bool      user_fin    = false;
    bool      server_fin  = false;
    bool      user_launch = true;   // true=用户发起SYN

    // ── 流量统计 ──────────────────────────────────────────
    uint32_t  ul_bytes    = 0;    // 上行总字节（含IP/TCP头）
    uint32_t  dl_bytes    = 0;    // 下行总字节
    uint32_t  ul_pkts     = 0;    // 上行总包数
    uint32_t  dl_pkts     = 0;    // 下行总包数
    uint32_t  ul_payload  = 0;    // 上行纯payload字节（HTTP用）
    uint32_t  dl_payload  = 0;    // 下行纯payload字节

    // ── 有效会话统计（有payload的包）─────────────────────
    uint32_t  eff_ul_bytes = 0;
    uint32_t  eff_dl_bytes = 0;
    uint32_t  eff_ul_pkts  = 0;
    uint32_t  eff_dl_pkts  = 0;

    // ── 重复包 ────────────────────────────────────────────
    uint32_t  dl_repeat_pkts = 0;

    // ── RTT追踪器 ─────────────────────────────────────────
    // user_rtt：下行数据包 → 上行ACK（用户侧RTT）
    // server_rtt：上行数据包 → 下行ACK（服务器侧RTT）
    RttTracker user_rtt;
    RttTracker server_rtt;

    // ── 丢包/乱序检测器 ───────────────────────────────────
    // ul_loss：检测上行包的丢包/乱序（服务器收到的视角）
    // dl_loss：检测下行包的丢包/乱序（用户收到的视角）
    LossDetector ul_loss;
    LossDetector dl_loss;

    // ── DCS输出方法 ───────────────────────────────────────

    // handshake_status 字段值（0~6）
    uint8_t hsStatusDcs() const {
        switch (hs_state) {
        case HsState::ESTABLISHED: return 0;
        case HsState::SRV_NO_RSP:  return 1;
        case HsState::SYN_SENT:    return 1;  // 超时未完成→服务器无响应
        case HsState::USR_NO_RSP:  return 2;
        case HsState::USR_RST:     return 3;
        case HsState::SRV_RST:     return 4;
        case HsState::EXCEPTION:   return 5;
        case HsState::INIT:        return 6;
        default:                   return 6;
        }
    }

    // socket_status 字段值（0~6）
    uint8_t sockStatusDcs() const {
        switch (sock_state) {
        case SockState::SUCCESS:    return 0;
        case SockState::ACTIVE:     return 0;  // 会话结束时映射为成功
        case SockState::SRV_NO_RSP: return 1;
        case SockState::USR_NO_RSP: return 2;
        case SockState::USR_RST:    return 3;
        case SockState::SRV_RST:    return 4;
        case SockState::EXCEPTION:  return 5;
        case SockState::INIT:       return 6;
        default:                    return 6;
        }
    }

    // 会话总时长（ms）：从第一个SYN到最后一个包
    uint32_t durationMs() const {
        uint64_t start = (create_us > 0) ? create_us : syn_ts_us;
        if (start == 0 || last_pkt_us <= start) return 0;
        return (uint32_t)((last_pkt_us - start) / 1000);
    }

    // 有效会话时长（ms）：第一个有payload包到最后一个有payload包
    uint32_t effDurationMs() const {
        if (first_data_us == 0 || last_data_us <= first_data_us)
            return 0;
        return (uint32_t)((last_data_us - first_data_us) / 1000);
    }

    void reset() {
        memset(this, 0, sizeof(*this));
        hs_state   = HsState::INIT;
        sock_state = SockState::INIT;
    }
};
