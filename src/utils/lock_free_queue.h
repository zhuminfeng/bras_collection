#pragma once

#include <atomic>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <type_traits>

// ─────────────────────────────────────────────────────────
// LockFreeQueue<T>
//
// 单生产者单消费者（SPSC）无锁环形队列
//
// 设计约束：
//   - 只有一个线程调用 push()  → WorkerThread / RadiusThread
//   - 只有一个线程调用 pop()   → OutputThread
//   - 满足上述约束时无需任何锁
//   - T 必须可平凡复制（memcpy安全）或可移动赋值
//
// 内存模型：
//   - head_：消费者读写（pop）
//   - tail_：生产者读写（push）
//   - 两者各自对齐到 cache line，避免 false sharing
//
// 容量：
//   - capacity 自动向上取整为2的幂次方
//   - 实际可用槽数 = capacity - 1（保留一个空槽区分满/空）
//
// 典型容量建议：
//   tcp_q / http_q / dns_q : 4096
//   onu_q / pppoe_q        : 1024
//   radius_q               : 4096
// ─────────────────────────────────────────────────────────
template<typename T>
class LockFreeQueue {
    static_assert(std::is_nothrow_move_assignable<T>::value ||
                  std::is_trivially_copyable<T>::value,
                  "T must be trivially copyable or nothrow move assignable");

public:
    // ── 构造 / 析构 ───────────────────────────────────────
    explicit LockFreeQueue(uint32_t capacity = 1024) {
        // 向上取整为2的幂
        uint32_t p = 1;
        while (p < capacity) p <<= 1;
        // 至少保证2个槽
        if (p < 2) p = 2;

        cap_  = p;
        mask_ = p - 1;
        buf_  = new T[p];
    }

    ~LockFreeQueue() {
        delete[] buf_;
    }

    // NonCopyable, NonMovable（持有原子变量）
    LockFreeQueue(const LockFreeQueue&)            = delete;
    LockFreeQueue& operator=(const LockFreeQueue&) = delete;
    LockFreeQueue(LockFreeQueue&&)                 = delete;
    LockFreeQueue& operator=(LockFreeQueue&&)      = delete;

    // ── push（生产者调用）─────────────���──────────────────
    // 返回 true：入队成功
    // 返回 false：队列已满（丢弃，调用方负责统计）
    bool push(const T& val) {
        uint32_t tail = tail_.load(std::memory_order_relaxed);
        uint32_t next = (tail + 1) & mask_;

        // 队列满：next == head
        if (next == head_.load(std::memory_order_acquire))
            return false;

        buf_[tail] = val;

        // release：保证 buf_[tail] 写入对消费者可见
        tail_.store(next, std::memory_order_release);
        return true;
    }

    // 移动语义版本（减少大对象拷贝开销）
    bool push(T&& val) {
        uint32_t tail = tail_.load(std::memory_order_relaxed);
        uint32_t next = (tail + 1) & mask_;

        if (next == head_.load(std::memory_order_acquire))
            return false;

        buf_[tail] = std::move(val);
        tail_.store(next, std::memory_order_release);
        return true;
    }

    // ── pop（消费者调用）─────────────────────────────────
    // 返回 true：出队成功，val 被填充
    // 返回 false：队列为空
    bool pop(T& val) {
        uint32_t head = head_.load(std::memory_order_relaxed);

        // 队列空：head == tail
        if (head == tail_.load(std::memory_order_acquire))
            return false;

        val = std::move(buf_[head]);

        // release：保证 val 读取完成后再更新 head
        head_.store((head + 1) & mask_,
                    std::memory_order_release);
        return true;
    }

    // ── 查询 ──────────────────────────────────────────────
    // 当前队列中的元素数（近似值，SPSC下是精确的）
    uint32_t size() const {
        uint32_t tail = tail_.load(std::memory_order_acquire);
        uint32_t head = head_.load(std::memory_order_acquire);
        return (tail - head + cap_) & mask_;
    }

    bool empty() const {
        return head_.load(std::memory_order_acquire) ==
               tail_.load(std::memory_order_acquire);
    }

    bool full() const {
        uint32_t tail = tail_.load(std::memory_order_relaxed);
        uint32_t next = (tail + 1) & mask_;
        return next == head_.load(std::memory_order_acquire);
    }

    // 队列容量（最大可用槽数 = cap - 1）
    uint32_t capacity() const { return cap_ - 1; }

private:
    // ── 避免 false sharing：head 和 tail 各占一个 cache line ─
    static constexpr uint32_t CACHE_LINE = 64;

    // 消费者端（head）
    alignas(CACHE_LINE) std::atomic<uint32_t> head_{0};

    // 生产者端（tail）
    alignas(CACHE_LINE) std::atomic<uint32_t> tail_{0};

    // 数据缓冲区
    T*       buf_  = nullptr;
    uint32_t cap_  = 0;   // 总槽数（2的幂）
    uint32_t mask_ = 0;   // cap - 1（用于取模）
};
