#include "radius_session_manager.h"
#include <spdlog/spdlog.h>
#include <vector>

RadiusSessionManager::RadiusSessionManager(uint64_t timeout_us,
                                             uint32_t capacity)
    : timeout_us_(timeout_us)
{
    uint32_t p = 1;
    while (p < capacity) p <<= 1;
    cap_  = p;
    mask_ = p - 1;
    table_.resize(cap_);
}

// ─────────────────────────────────────────────────────────
// 内部：探测槽位
// ─────────────────────────────────────────────────────────
uint32_t RadiusSessionManager::probe(uint32_t ip, uint8_t id,
                                      bool* found) const
{
    *found = false;
    uint32_t start      = hash(ip, id);
    uint32_t first_tomb = UINT32_MAX;

    for (uint32_t i = 0; i < 32; ++i) {
        uint32_t idx = (start + i) & mask_;
        const Entry& e = table_[idx];

        if (e.is_tombstone) {
            if (first_tomb == UINT32_MAX) first_tomb = idx;
            continue;
        }
        if (!e.in_use) {
            return (first_tomb != UINT32_MAX) ? first_tomb : idx;
        }
        if (e.rec.client_ip == ip && e.rec.radius_id == id) {
            *found = true;
            return idx;
        }
    }
    return (first_tomb != UINT32_MAX) ? first_tomb : UINT32_MAX;
}

// ─────────────────────────────────────────────────────────
// 处理一个 Radius 包
// ─────────────────────────────────────────────────────────
void RadiusSessionManager::onPacket(const RadiusRecord& pkt,
                                     const CompleteFn&   on_complete)
{
    // Radius代码分类：
    //   请求：1(Auth-Request) 4(Acct-Request) 10(CoA-Request)
    //   响应：2(Auth-Accept) 3(Auth-Reject) 5(Acct-Response)
    //         11(Auth-Challenge) 40-45(Disconnect/CoA)
    bool is_request = (pkt.request_code == 1  ||
                       pkt.request_code == 4  ||
                       pkt.request_code == 10 ||
                       pkt.request_code == 40 ||
                       pkt.request_code == 43);
    bool is_response= (pkt.reply_code   != 0);

    if (is_request && !is_response) {
        // ── 请求包：存入待匹配表 ──────────────────────────
        bool     found = false;
        uint32_t idx   = probe(pkt.client_ip, pkt.radius_id,
                               &found);

        if (idx == UINT32_MAX) {
            spdlog::warn("[RadiusMgr] table full, dropping request "
                         "id={}", pkt.radius_id);
            return;
        }

        Entry& e = table_[idx];
        if (e.is_tombstone) {
            --tombstones_;
        } else if (!e.in_use) {
            ++used_;
        }
        // 如果found=true说明有未响应的旧请求，直接覆盖
        // （NAS重传时radius_id相同）
        e.rec      = pkt;
        e.in_use   = true;
        e.is_tombstone = false;

    } else if (is_response) {
        // ── 响应包：查找对应请求合并输出 ─────────────────
        // 响应包的 client_ip = NAS IP（存在 bras_ip 字段），
        // radius_id 与请求包相同
        bool     found = false;
        uint32_t idx   = probe(pkt.bras_ip, pkt.radius_id,
                               &found);

        if (!found) {
            // 无对应请求（可能是重复响应或采集丢包）
            // 仍然输出：start_time=0，end_time=响应时间
            on_complete(pkt);
            return;
        }

        // 合并：请求字段 + 响应字段
        Entry& e = table_[idx];
        RadiusRecord merged = e.rec;

        // 从响应包填写响应字段
        merged.end_time    = pkt.end_time;
        merged.reply_code  = pkt.reply_code;

        // 响应包可能携带额外AVP（如framed_ip, reply_message）
        // 只覆盖非零/非空字段
        if (merged.framed_ip == 0 && pkt.framed_ip != 0)
            merged.framed_ip = pkt.framed_ip;
        if (merged.reply_message[0] == '\0' &&
            pkt.reply_message[0] != '\0')
            strncpy(merged.reply_message, pkt.reply_message,
                    sizeof(merged.reply_message) - 1);
        if (merged.session_timeout == 0 && pkt.session_timeout != 0)
            merged.session_timeout = pkt.session_timeout;
        if (merged.idle_timeout == 0 && pkt.idle_timeout != 0)
            merged.idle_timeout = pkt.idle_timeout;

        // 计算 hour/min 时间戳（用start_time）
        // start_time 已在请求包解析时填好

        on_complete(merged);

        // 标记为墓碑
        e.in_use       = false;
        e.is_tombstone = true;
        ++tombstones_;
        --used_;
    }
}

// ─────────────────────────────────────────────────────────
// 清理超时请求（超时未收到响应直接输出）
// ─────────────────────────────────────────────────────────
void RadiusSessionManager::purgeExpired(uint64_t now_us,
                                         const CompleteFn& on_complete)
{
    uint32_t purged = 0;
    for (uint32_t i = 0; i < cap_; ++i) {
        Entry& e = table_[i];
        if (!e.in_use || e.is_tombstone) continue;

        double start_us = e.rec.start_time * 1e6;
        if (now_us - (uint64_t)start_us >= timeout_us_) {
            // 超时：end_time=0，reply_code=0（无响应）
            on_complete(e.rec);

            e.in_use       = false;
            e.is_tombstone = true;
            ++tombstones_;
            --used_;
            ++purged;
        }
    }
    if (purged > 0) {
        spdlog::debug("[RadiusMgr] purged {} timed-out requests",
                      purged);
    }
}

// ─────────────────────────────────────────────────────────
// 清理所有（程序退出）
// ─────────────────────────────────────────────────────────
void RadiusSessionManager::purgeAll(const CompleteFn& on_complete) {
    for (uint32_t i = 0; i < cap_; ++i) {
        Entry& e = table_[i];
        if (!e.in_use || e.is_tombstone) continue;
        on_complete(e.rec);
        e.in_use = false;
    }
    used_       = 0;
    tombstones_ = 0;
}
