#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include "../core/dpdk_engine.h" // DpdkPortConfig

struct CollectorConfig
{
	// ── DPDK ──────────────────────────────────
	std::vector<DpdkPortConfig> port_configs;
	uint16_t nb_rx_queues = 4;
	uint16_t nb_workers = 4;

	// ── 网络拓扑 ──────────────────────────────
	uint32_t bras_network = 0; // 网络字节序
	uint32_t bras_netmask = 0;
	std::vector<uint32_t> radius_ips;
	uint16_t radius_port = 1812;

	// ── 硬件特性 ──────────────────────────────
	bool hw_flow_steering = false;
	uint16_t radius_queue = 0;
	uint16_t pppoe_queue = 1;
	uint16_t worker_queue_start = 2;

	// ── 输出 ──────────────────────────────────
	std::string raw_dir = "./raw";
	std::string log_dir = "./logs";
	std::string collector_id = ""; // 采集机编号（空或两位数字）

	// ── 运行参数 ──────────────────────────────
	uint32_t flow_timeout_sec = 120;
	uint32_t purge_interval_sec = 5;
	uint32_t file_rotate_sec = 60;

	// 从JSON文件加载
	void load(const std::string &path);

	// 校验配置合法性，失败抛异常
	void validate() const;

	// 工具：点分十进制IP→uint32_t（主机序）
	static uint32_t parseIp(const std::string &s);
};