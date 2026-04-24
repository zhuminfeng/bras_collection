#pragma once
#include <cstdint>
#include <cstring>
#include <atomic>

// ─────────────────────────────────────────────
// 全局常量
// ─────────────────────────────────────────────
static constexpr uint16_t MAX_PORTS = 4;
static constexpr uint16_t MAX_QUEUES = 32;
static constexpr uint16_t MAX_WORKERS = 64;
static constexpr uint16_t BURST_SIZE = 64;
static constexpr uint32_t MBUF_CACHE_SIZE = 512;
static constexpr uint32_t MBUF_POOL_SIZE = 524288;			  // 512K/队列
static constexpr uint32_t RING_SIZE = 16384;				  // 必须2的幂
static constexpr uint32_t FLOW_TABLE_CAP = 1 << 20;			  // 1M流槽
static constexpr uint64_t FLOW_TIMEOUT_US = 120ULL * 1000000; // 120s
static constexpr uint64_t PURGE_INTERVAL_US = 5ULL * 1000000; // 5s
static constexpr uint32_t FILE_ROTATE_SEC = 60;				  // 每分钟轮转

// ─────────────────────────────────────────────
// 包类型标记（分流器使用）
// ─────────────────────────────────────────────
enum PktType : uint8_t
{
	PKT_USER = 0,
	PKT_RADIUS = 1,
	PKT_PPPOE = 2,
	PKT_DNS = 3,
	PKT_INVALID = 0xFF,
};

// ─────────────────────────────────────────────
// 方向定义
// ─────────────────────────────────────────────
enum Direction : uint8_t
{
	DIR_UPSTREAM = 0,	// 用户 → 服务器
	DIR_DOWNSTREAM = 1, // 服务器 → 用户
	DIR_UNKNOWN = 0xFF,
};

// ─────────────────────────────────────────────
// 协议编号（扩展IPPROTO_*）
// ─────────────────────────────────────────────
static constexpr uint8_t PROTO_TCP = 6;
static constexpr uint8_t PROTO_UDP = 17;
static constexpr uint8_t PROTO_ICMP = 1;

// ─────────────────────────────────────────────
// 线程状态
// ─────────────────────────────────────────────
enum class ThreadState : uint8_t
{
	IDLE = 0,
	RUNNING = 1,
	STOPPED = 2,
	ERROR = 3,
};

// ─────────────────────────────────────────────
// 禁止拷贝的基类
// ─────────────────────────────────────────────
class NonCopyable
{
protected:
	NonCopyable() = default;
	~NonCopyable() = default;
	NonCopyable(const NonCopyable &) = delete;
	NonCopyable &operator=(const NonCopyable &) = delete;
};

// ─────────────────────────────────────────────
// 简单无锁SPSC队列（OutputThread用）
// T 必须可平凡拷贝
// ─────────────────────────────────────────────
template <typename T, uint32_t CAP>
class SpscQueue : NonCopyable
{
	static_assert((CAP & (CAP - 1)) == 0, "CAP must be power of 2");

public:
	bool push(const T &val)
	{
		uint32_t head = head_.load(std::memory_order_relaxed);
		uint32_t next = (head + 1) & (CAP - 1);
		if (next == tail_.load(std::memory_order_acquire))
			return false;
		buf_[head] = val;
		head_.store(next, std::memory_order_release);
		return true;
	}

	bool pop(T &val)
	{
		uint32_t tail = tail_.load(std::memory_order_relaxed);
		if (tail == head_.load(std::memory_order_acquire))
			return false;
		val = buf_[tail];
		tail_.store((tail + 1) & (CAP - 1), std::memory_order_release);
		return true;
	}

	uint32_t size() const
	{
		uint32_t h = head_.load(std::memory_order_relaxed);
		uint32_t t = tail_.load(std::memory_order_relaxed);
		return (h - t) & (CAP - 1);
	}

	bool empty() const { return size() == 0; }

private:
	alignas(64) std::atomic<uint32_t> head_{0};
	alignas(64) std::atomic<uint32_t> tail_{0};
	T buf_[CAP];
};