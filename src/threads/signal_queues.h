#pragma once

#include "../utils/lock_free_queue.h"
#include "../record/record_types.h"

// ─────────────────────────────────────────────────────────
// SignalOutputQueues
//
// RadiusThread（生产者）→ OutputThread（消费者）
// 包含 Radius 计费报文和 PPPoE 信令两类记录
// ─────────────────────────────────────────────────────────
struct SignalOutputQueues
{
	LockFreeQueue<RadiusRecord> radius_q{4096};
	LockFreeQueue<PPPoERecord> pppoe_q{1024};

	SignalOutputQueues() = default;
	SignalOutputQueues(const SignalOutputQueues &) = delete;
	SignalOutputQueues &operator=(const SignalOutputQueues &) = delete;
};
