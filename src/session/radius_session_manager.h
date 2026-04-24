#pragma once

#include "../record/radius_record.h"
#include <cstdint>
#include <cstring>
#include <functional>

// ─────────────────────────────────────────────────────────
// RadiusSessionManager
//
// 职责：将 Radius 请求包和响应包配对，合并为一条 RadiusRecord
//
// 匹配 key：(client_ip, radius_id)
//   client_ip = NAS IP（请求方）
//   radius_id = Radius Identifier（0~255，NAS自增分配）
//
// 超时处理：
//   请求包超过 timeout_us 未收到响应 → 直接输出（end_time=0）
//   响应包无对应请求 → 丢弃
//
// 实现：
//   固定大小哈希表（开放地址法），单线程使用
//   capacity = 65536（256 NAS * 256 ID）
// ─────────────────────────────────────────────────────────
class RadiusSessionManager {
public:
    // on_complete：配对完成或超时时的回调（用于写DCS）
    using CompleteFn = std::function<void(const RadiusRecord&)>;

    explicit RadiusSessionManager(
        uint64_t   timeout_us  = 5ULL * 1000000,  // 5秒
        uint32_t   capacity    = 1 << 16);         // 65536槽

    ~RadiusSessionManager() = default;

    // 处理一个 Radius 包（请求或响应）
    // 内部自动判断：请求→存入pending；响应→与pending合并→回调
    void onPacket(const RadiusRecord& pkt,
                  const CompleteFn&   on_complete);

    // 定期调用：清理超时的未响应请求
    void purgeExpired(uint64_t   now_us,
                      const CompleteFn& on_complete);

    // 清理所有（程序退出）
    void purgeAll(const CompleteFn& on_complete);

    uint32_t pendingCount() const { return used_; }

private:
    struct Entry {
        RadiusRecord rec;
        bool         in_use     = false;
        bool         is_tombstone = false;
    };

    // 哈希 key = (client_ip, radius_id)
    uint32_t hash(uint32_t ip, uint8_t id) const {
        uint32_t h = (ip ^ ((uint32_t)id << 24));
        h ^= h >> 16; h *= 0x45d9f3b; h ^= h >> 16;
        return h & mask_;
    }

    // 查找槽位（返回UINT32_MAX=表满）
    uint32_t probe(uint32_t ip, uint8_t id,
                   bool* found) const;

    std::vector<Entry> table_;
    uint32_t           cap_;
    uint32_t           mask_;
    uint32_t           used_       = 0;
    uint32_t           tombstones_ = 0;
    uint64_t           timeout_us_;
};
