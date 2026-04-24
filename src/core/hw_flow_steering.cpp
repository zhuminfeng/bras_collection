#include "hw_flow_steering.h"
#include <rte_flow.h>
#include <rte_log.h>
#include <cstring>
#include <stdexcept>

HwFlowSteering::HwFlowSteering(uint16_t port_id)
	: port_id_(port_id)
{
	// 检查 ConnectX-5 是否支持 rte_flow
	struct rte_flow_error err{};
	struct rte_flow_attr attr{.ingress = 1};
	if (rte_flow_validate(port_id, &attr, nullptr, nullptr, &err) != -ENOTSUP)
	{
		supported_ = true;
	}
}

HwFlowSteering::~HwFlowSteering()
{
	destroyAllRules();
}

// ─────────────────────────────────────────────────────────
// Radius规则：UDP目的端口 1812 或 1813 → 专用队列
// ─────────────────────────────────────────────────────────
bool HwFlowSteering::addRadiusRule(uint16_t target_queue)
{
	// 规则1：dst_port=1812
	auto *r1 = createUdpPortRule(1812, target_queue, 1);
	// 规则2：dst_port=1813（计费）
	auto *r2 = createUdpPortRule(1813, target_queue, 1);
	// 规则3：src_port=1812（响应方向）
	auto *r3 = createUdpPortRule(1812, target_queue, 1); // src方向另写

	if (!r1 || !r2)
	{
		RTE_LOG(ERR, USER1, "Failed to create Radius flow rules\n");
		return false;
	}
	if (r1)
		rules_.push_back(r1);
	if (r2)
		rules_.push_back(r2);
	if (r3)
		rules_.push_back(r3);

	RTE_LOG(INFO, USER1,
			"HW Radius flow rule: UDP 1812/1813 → queue %u\n",
			target_queue);
	return true;
}

struct rte_flow *HwFlowSteering::createUdpPortRule(
	uint16_t dst_port,
	uint16_t target_queue,
	uint32_t priority)
{
	struct rte_flow_error err{};
	struct rte_flow_attr attr{};
	attr.ingress = 1;
	attr.priority = priority;

	// ── pattern：ETH / IP / UDP(dst_port=X) ─────────────
	struct rte_flow_item_eth eth_spec{}, eth_mask{};
	struct rte_flow_item_ipv4 ip_spec{}, ip_mask{};
	struct rte_flow_item_udp udp_spec{}, udp_mask{};

	// UDP目的端口匹配
	udp_spec.hdr.dst_port = rte_cpu_to_be_16(dst_port);
	udp_mask.hdr.dst_port = 0xFFFF;

	struct rte_flow_item pattern[] = {
		{RTE_FLOW_ITEM_TYPE_ETH, &eth_spec, &eth_mask, nullptr},
		{RTE_FLOW_ITEM_TYPE_IPV4, &ip_spec, &ip_mask, nullptr},
		{RTE_FLOW_ITEM_TYPE_UDP, &udp_spec, &udp_mask, nullptr},
		{RTE_FLOW_ITEM_TYPE_END, nullptr, nullptr, nullptr}};

	// ── action：QUEUE（直接入指定队列）+ MARK（标记来源）──
	struct rte_flow_action_queue queue_action{.index = target_queue};
	struct rte_flow_action_mark mark_action{
		.id = (dst_port == 1812 || dst_port == 1813)
				  ? (uint32_t)0xCAFE1 // Radius标记
				  : (uint32_t)0xCAFE2 // 其他
	};

	struct rte_flow_action actions[] = {
		{RTE_FLOW_ACTION_TYPE_MARK, &mark_action},
		{RTE_FLOW_ACTION_TYPE_QUEUE, &queue_action},
		{RTE_FLOW_ACTION_TYPE_END, nullptr}};

	// 校验规则可行性
	if (rte_flow_validate(port_id_, &attr, pattern, actions, &err) != 0)
	{
		RTE_LOG(WARNING, USER1,
				"Flow rule validate failed: %s\n", err.message);
		return nullptr;
	}

	return rte_flow_create(port_id_, &attr, pattern, actions, &err);
}

// ─────────────────────────────────────────────────────────
// PPPoE规则：EtherType 0x8863/0x8864 → 专用队列
// ─────────────────────────────────────────────────────────
bool HwFlowSteering::addPPPoERule(uint16_t target_queue)
{
	auto *r1 = createEtherTypeRule(0x8863, target_queue, 1); // Discovery
	auto *r2 = createEtherTypeRule(0x8864, target_queue, 1); // Session

	if (r1)
		rules_.push_back(r1);
	if (r2)
		rules_.push_back(r2);

	RTE_LOG(INFO, USER1,
			"HW PPPoE flow rule: 0x8863/8864 → queue %u\n", target_queue);
	return (r1 && r2);
}

struct rte_flow *HwFlowSteering::createEtherTypeRule(
	uint16_t ethertype,
	uint16_t target_queue,
	uint32_t priority)
{
	struct rte_flow_error err{};
	struct rte_flow_attr attr{.ingress = 1, .priority = priority};

	struct rte_flow_item_eth eth_spec{}, eth_mask{};
	eth_spec.type = rte_cpu_to_be_16(ethertype);
	eth_mask.type = 0xFFFF;

	struct rte_flow_item pattern[] = {
		{RTE_FLOW_ITEM_TYPE_ETH, &eth_spec, &eth_mask, nullptr},
		{RTE_FLOW_ITEM_TYPE_END, nullptr, nullptr, nullptr}};

	struct rte_flow_action_queue queue_action{.index = target_queue};
	struct rte_flow_action actions[] = {
		{RTE_FLOW_ACTION_TYPE_QUEUE, &queue_action},
		{RTE_FLOW_ACTION_TYPE_END, nullptr}};

	return rte_flow_create(port_id_, &attr, pattern, actions, &err);
}

// ─────────────────────────────────────────────────────────
// 默认规则：剩余流量按RSS分发到Worker队列组
// ─────────────────────────────────────────────────────────
bool HwFlowSteering::addDefaultRssRule(
	const std::vector<uint16_t> &worker_queues)
{
	struct rte_flow_error err{};
	struct rte_flow_attr attr{
		.ingress = 1,
		.priority = 3 // 低优先级，作为catch-all
	};

	// 匹配所有包
	struct rte_flow_item pattern[] = {
		{RTE_FLOW_ITEM_TYPE_ETH, nullptr, nullptr, nullptr},
		{RTE_FLOW_ITEM_TYPE_END, nullptr, nullptr, nullptr}};

	// RSS action：按对称哈希分发到worker队列
	std::vector<uint16_t> queues = worker_queues;

	struct rte_flow_action_rss rss_action{};
	rss_action.func = RTE_ETH_HASH_FUNCTION_TOEPLITZ;
	rss_action.level = 0;
	rss_action.types = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP;
	rss_action.key_len = 40;
	rss_action.key = MLX5_SYM_RSS_KEY; // 复用对称键
	rss_action.queue_num = (uint32_t)queues.size();
	rss_action.queue = queues.data();

	struct rte_flow_action actions[] = {
		{RTE_FLOW_ACTION_TYPE_RSS, &rss_action},
		{RTE_FLOW_ACTION_TYPE_END, nullptr}};

	auto *rule = rte_flow_create(port_id_, &attr, pattern, actions, &err);
	if (!rule)
	{
		RTE_LOG(ERR, USER1, "Default RSS rule failed: %s\n", err.message);
		return false;
	}
	rules_.push_back(rule);
	return true;
}

void HwFlowSteering::destroyAllRules()
{
	struct rte_flow_error err{};
	for (auto *r : rules_)
	{
		rte_flow_destroy(port_id_, r, &err);
	}
	rules_.clear();
}