#pragma once
#include <rte_flow.h>
#include <vector>
#include <cstdint>

// ConnectX-5 硬件流分类规则管理
// 将特定流量在NIC内部直接引导到指定队列，不消耗CPU
class HwFlowSteering
{
public:
	explicit HwFlowSteering(uint16_t port_id);
	~HwFlowSteering();

	// 将 Radius 流量（UDP 1812/1813）引导到专用队列
	bool addRadiusRule(uint16_t target_queue);

	// 将 PPPoE 发现帧引导到专用队列
	bool addPPPoERule(uint16_t target_queue);

	// 将 DNS 流量（UDP 53）引导到指定队列组
	bool addDnsRule(uint16_t target_queue);

	// 其余流量按 RSS 分配到 worker 队列组
	bool addDefaultRssRule(const std::vector<uint16_t> &worker_queues);

	void destroyAllRules();

	bool isSupported() const { return supported_; }

private:
	struct rte_flow *createUdpPortRule(
		uint16_t dst_port,
		uint16_t target_queue,
		uint32_t priority);

	struct rte_flow *createEtherTypeRule(
		uint16_t ethertype,
		uint16_t target_queue,
		uint32_t priority);

	uint16_t port_id_;
	std::vector<struct rte_flow *> rules_;
	bool supported_ = false;
};