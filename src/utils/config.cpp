#include "config.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <stdexcept>
#include <arpa/inet.h>
#include <spdlog/spdlog.h>

using json = nlohmann::json;

uint32_t CollectorConfig::parseIp(const std::string& s)
{
    struct in_addr addr{};
    if (inet_pton(AF_INET, s.c_str(), &addr) != 1)
        throw std::runtime_error("Invalid IP: " + s);
    return ntohl(addr.s_addr);
}

void CollectorConfig::load(const std::string& path)
{
    std::ifstream f(path);
    if (!f.is_open())
        throw std::runtime_error("Cannot open config: " + path);

    json j;
    f >> j;

    // ── workers ───────────────────────────────
    nb_workers   = j.value("nb_workers",   4);
    nb_rx_queues = j.value("nb_rx_queues", 4);
    collector_id = j.value("collector_id", std::string(""));
    log_dir      = j.value("log_dir",      std::string("./logs"));

    // ★ raw_dir：兼容旧 key "output_dir"
    if (j.contains("raw_dir"))
        raw_dir = j["raw_dir"].get<std::string>();
    else if (j.contains("output_dir"))
        raw_dir = j["output_dir"].get<std::string>();
    else
        raw_dir = "./raw";

    flow_timeout_sec   = j.value("flow_timeout_sec",   120);
    purge_interval_sec = j.value("purge_interval_sec", 5);

    // ★ file_rotate_sec：兼容旧 key "file_rotate_seconds"
    if (j.contains("file_rotate_sec"))
        file_rotate_sec = j["file_rotate_sec"].get<uint32_t>();
    else if (j.contains("file_rotate_seconds"))
        file_rotate_sec = j["file_rotate_seconds"].get<uint32_t>();
    else
        file_rotate_sec = 60;

    // ★ rotate_interval 与 file_rotate_sec 保持同步
    rotate_interval = file_rotate_sec;

    // ★ ONU 软探针 URL 前缀
    onu_url_prefix = j.value("onu_url_prefix", std::string("/report"));

    // ── 网络拓扑 ──────────────────────────────
    if (j.contains("bras_network"))
        bras_network = parseIp(j["bras_network"].get<std::string>());
    if (j.contains("bras_netmask"))
        bras_netmask = parseIp(j["bras_netmask"].get<std::string>());

    for (auto& ip : j.value("radius_server_ips", json::array()))
        radius_ips.push_back(parseIp(ip.get<std::string>()));
    radius_port = j.value("radius_port", 1812);

    // ── 硬件分流 ──────────────────────────────
    hw_flow_steering   = j.value("hw_flow_steering",   false);
    radius_queue       = j.value("radius_queue",       0);
    pppoe_queue        = j.value("pppoe_queue",        1);
    worker_queue_start = j.value("worker_queue_start", 2);

    // ── 端口配置 ──────────────────────────────
    for (auto& p : j.value("ports", json::array()))
    {
        DpdkPortConfig pc{};
        // ★ 兼容有/无 port_id 的 json 格式
        pc.port_id       = p.value("port_id",       0);
        pc.nb_rx_queues  = p.value("nb_rx_queues",  nb_rx_queues);
        pc.nb_tx_queues  = 0;
        pc.rx_desc       = p.value("rx_desc",       4096);
        pc.promiscuous   = p.value("promiscuous",   true);
        pc.mbuf_pool_size= p.value("mbuf_pool_size",MBUF_POOL_SIZE);
        port_configs.push_back(pc);
    }

    if (port_configs.empty())
    {
        DpdkPortConfig pc{};
        pc.port_id       = 0;
        pc.nb_rx_queues  = nb_rx_queues;
        pc.rx_desc       = 4096;
        pc.promiscuous   = true;
        pc.mbuf_pool_size= MBUF_POOL_SIZE;
        port_configs.push_back(pc);
    }

    spdlog::info("Config loaded: workers={} rx_queues={} "
                 "raw_dir={} rotate={}s onu_prefix={}",
                 nb_workers, nb_rx_queues,
                 raw_dir, rotate_interval, onu_url_prefix);
}

void CollectorConfig::validate() const
{
    if (nb_workers == 0 || nb_workers > MAX_WORKERS)
        throw std::runtime_error("nb_workers out of range");
    if (port_configs.empty())
        throw std::runtime_error("No port configured");
    if (raw_dir.empty())
        throw std::runtime_error("raw_dir not set");
    if (rotate_interval == 0)
        throw std::runtime_error("rotate_interval must be > 0");
}
