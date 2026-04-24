#include "config.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <stdexcept>
#include <arpa/inet.h>
#include <spdlog/spdlog.h>

using json = nlohmann::json;

uint32_t CollectorConfig::parseIp(const std::string &s)
{
	struct in_addr addr{};
	if (inet_pton(AF_INET, s.c_str(), &addr) != 1)
		throw std::runtime_error("Invalid IP: " + s);
	return ntohl(addr.s_addr);
}

void CollectorConfig::load(const std::string &path)
{
	std::ifstream f(path);
	if (!f.is_open())
		throw std::runtime_error("Cannot open config: " + path);

	json j;
	f >> j;

	// ── workers ───────────────────────────────
	nb_workers = j.value("nb_workers", 4);
	nb_rx_queues = j.value("nb_rx_queues", 4);
	collector_id = j.value("collector_id", "");
	raw_dir = j.value("raw_dir", "./raw");
	log_dir = j.value("log_dir", "./logs");
	flow_timeout_sec = j.value("flow_timeout_sec", 120);
	purge_interval_sec = j.value("purge_interval_sec", 5);
	file_rotate_sec = j.value("file_rotate_sec", 60);

	// ── 网络拓扑 ──────────────────────────────
	if (j.contains("bras_network"))
		bras_network = parseIp(j["bras_network"].get<std::string>());
	if (j.contains("bras_netmask"))
		bras_netmask = parseIp(j["bras_netmask"].get<std::string>());

	for (auto &ip : j.value("radius_server_ips", json::array()))
		radius_ips.push_back(parseIp(ip.get<std::string>()));
	radius_port = j.value("radius_port", 1812);

	// ── 硬件分流 ──────────────────────────────
	hw_flow_steering = j.value("hw_flow_steering", false);
	radius_queue = j.value("radius_queue", 0);
	pppoe_queue = j.value("pppoe_queue", 1);
	worker_queue_start = j.value("worker_queue_start", 2);

	// ── 端口配置 ──────────────────────────────
	for (auto &p : j.value("ports", json::array()))
	{
		DpdkPortConfig pc{};
		pc.port_id = p.value("port_id", 0);
		pc.nb_rx_queues = p.value("nb_rx_queues", nb_rx_queues);
		pc.nb_tx_queues = 0;
		pc.rx_desc = p.value("rx_desc", 4096);
		pc.promiscuous = p.value("promiscuous", true);
		pc.mbuf_pool_size = p.value("mbuf_pool_size", MBUF_POOL_SIZE);
		port_configs.push_back(pc);
	}

	if (port_configs.empty())
	{
		// 默认：port 0
		DpdkPortConfig pc{};
		pc.port_id = 0;
		pc.nb_rx_queues = nb_rx_queues;
		pc.rx_desc = 4096;
		pc.promiscuous = true;
		pc.mbuf_pool_size = MBUF_POOL_SIZE;
		port_configs.push_back(pc);
	}

	spdlog::info("Config loaded: workers={} rx_queues={} raw_dir={}",
				 nb_workers, nb_rx_queues, raw_dir);
}

void CollectorConfig::validate() const
{
	if (nb_workers == 0 || nb_workers > MAX_WORKERS)
		throw std::runtime_error("nb_workers out of range");
	if (port_configs.empty())
		throw std::runtime_error("No port configured");
	if (raw_dir.empty())
		throw std::runtime_error("raw_dir not set");
}