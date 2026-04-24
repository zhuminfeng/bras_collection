#include "raw_file_manager.h"
#include "tcp_dcs_serializer.h"
#include "http_dcs_serializer.h"
#include "radius_dcs_serializer.h"
#include "onu_dcs_serializer.h"
#include "../utils/time_utils.h"
#include <spdlog/spdlog.h>
#include <filesystem>
#include <cstring>
#include <cstdio>

// ─────────────────────────────────────────────────────────
// 构造
// ─────────────────────────────────────────────────────────
RawFileManager::RawFileManager(const std::string& raw_dir,
                                const std::string& collector_id)
    : raw_dir_(raw_dir), collector_id_(collector_id)
{
    std::filesystem::create_directories(raw_dir_);

    // 用当前时间初始化（首次打开文件）
    time_t now   = time(nullptr);
    uint32_t min_ts = (uint32_t)(now - now % 60);
    initWriters(min_ts);
}

RawFileManager::~RawFileManager() {
    shutdown();
}

// ─────────────────────────────────────────────────────────
// 初始化所有协议的 DcsWriter
// ─────────────────────────────────────────────────────────
void RawFileManager::initWriters(uint32_t min_round_sec) {
    last_min_ts_ = min_round_sec;

    http_  .writer = std::make_unique<DcsWriter>("http",   raw_dir_, collector_id_);
    tcp_   .writer = std::make_unique<DcsWriter>("tcp",    raw_dir_, collector_id_);
    radius_.writer = std::make_unique<DcsWriter>("radius", raw_dir_, collector_id_);
    onu_   .writer = std::make_unique<DcsWriter>("onu",    raw_dir_, collector_id_);
    dns_   .writer = std::make_unique<DcsWriter>("dns",    raw_dir_, collector_id_);
    udp_   .writer = std::make_unique<DcsWriter>("udp",    raw_dir_, collector_id_);
    pppoe_ .writer = std::make_unique<DcsWriter>("pppoe",  raw_dir_, collector_id_);

    http_  .writer->rotate(min_round_sec);
    tcp_   .writer->rotate(min_round_sec);
    radius_.writer->rotate(min_round_sec);
    onu_   .writer->rotate(min_round_sec);
    dns_   .writer->rotate(min_round_sec);
    udp_   .writer->rotate(min_round_sec);
    pppoe_ .writer->rotate(min_round_sec);
}

// ─────────────────────────────────────────────────────────
// 分钟轮转
// ─────────────────────────────────────────────────────────
void RawFileManager::rotateIfNeeded(uint32_t min_round_sec) {
    if (min_round_sec <= last_min_ts_) return;

    spdlog::info("[RawFileManager] rotating to min_ts={}",
                 min_round_sec);

    auto rotate = [&](WriterSlot& slot) {
        std::lock_guard<std::mutex> lk(slot.mu);
        slot.writer->rotate(min_round_sec);
    };

    rotate(http_);
    rotate(tcp_);
    rotate(radius_);
    rotate(onu_);
    rotate(dns_);
    rotate(udp_);
    rotate(pppoe_);

    last_min_ts_ = min_round_sec;
}

// ─────────────────────────────────────────────────────────
// 通用写入辅助
// ─────────────────────────────────────────────────────────
template<typename SerFn>
void RawFileManager::writeToSlot(WriterSlot& slot,
                                  SerFn&&     serialize_fn)
{
    char buf[SER_BUF_SIZE];
    size_t len = serialize_fn(buf, SER_BUF_SIZE);
    if (len == 0) return;

    std::lock_guard<std::mutex> lk(slot.mu);
    slot.writer->writeLine(buf, len);
}

// ─────────────────────────────────────────────────────────
// HTTP 写入
// ─────────────────────────────────────────────────────────
void RawFileManager::writeHttp(const HttpRecord& rec) {
    writeToSlot(http_, [&](char* buf, size_t sz) -> size_t {
        return HttpDcsSerializer::serialize(rec, buf, sz);
    });
}

// ─────────────────────────────────────────────────────────
// TCP 写入
// ─────────────────────────────────────────────────────────
void RawFileManager::writeTcp(const TcpSessionRecord& rec) {
    writeToSlot(tcp_, [&](char* buf, size_t sz) -> size_t {
        return TcpDcsSerializer::serialize(rec, buf, sz);
    });
}

// ─────────────────────────────────────────────────────────
// Radius 写入
// ─────────────────────────────────────────────────────────
void RawFileManager::writeRadius(const RadiusRecord& rec) {
    writeToSlot(radius_, [&](char* buf, size_t sz) -> size_t {
        return RadiusDcsSerializer::serialize(rec, buf, sz);
    });
}

// ─────────────────────────────────────────────────────────
// ONU 写入
// ─────────────────────────────────────────────────────────
void RawFileManager::writeOnu(const OnuRecord& rec) {
    writeToSlot(onu_, [&](char* buf, size_t sz) -> size_t {
        return OnuDcsSerializer::serialize(rec, buf, sz);
    });
}

// ─────────────────────────────────────────────────────────
// DNS 写入
// ─────────────────────────────────────────────────────────
void RawFileManager::writeDns(const DnsRecord& rec) {
    writeToSlot(dns_, [&](char* buf, size_t sz) -> size_t {
        return (size_t)snprintf(buf, sz,
            "%lu\t%u\t%u\t%s\t%u\t%u\t%u\t%s",
            rec.query_time,
            rec.user_ip,
            rec.dns_server_ip,
            rec.query_name[0] ? rec.query_name : "NONE",
            (unsigned)rec.query_type,
            (unsigned)rec.result_code,
            rec.response_duration_us,
            rec.answers[0]    ? rec.answers     : "NONE");
    });
}

// ─────────────────────────────────────────────────────────
// UDP 写入
// ─────────────────────────────────────────────────────────
void RawFileManager::writeUdp(const UdpStreamRecord& rec) {
    writeToSlot(udp_, [&](char* buf, size_t sz) -> size_t {
        return (size_t)snprintf(buf, sz,
            "%lu\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%.4f\t%u",
            rec.start_time,
            rec.user_ip,
            rec.server_ip,
            rec.user_port,
            rec.server_port,
            rec.ndpi_app_proto,
            (unsigned)rec.traffic_type,
            rec.expected_pkts,
            rec.received_pkts,
            rec.loss_rate,
            rec.duration_ms);
    });
}

// ─────────────────────────────────────────────────────────
// PPPoE 写入
// ─────────────────────────────────────────────────────────
void RawFileManager::writePPPoE(const PPPoERecord& rec) {
    writeToSlot(pppoe_, [&](char* buf, size_t sz) -> size_t {
        return (size_t)snprintf(buf, sz,
            "%lu\t%u\t%lu\t%lu\t%u\t%s\t%s",
            rec.event_time,
            (unsigned)rec.event_type,
            rec.client_mac,
            rec.server_mac,
            rec.session_id,
            rec.ac_name[0]      ? rec.ac_name      : "NONE",
            rec.service_name[0] ? rec.service_name  : "NONE");
    });
}

// ─────────────────────────────────────────────────────────
// 刷盘 / 关闭
// ─────────────────────────────────────────────────────────
void RawFileManager::flushAll() {
    auto flush = [](WriterSlot& slot) {
        std::lock_guard<std::mutex> lk(slot.mu);
        slot.writer->flush();
    };
    flush(http_);
    flush(tcp_);
    flush(radius_);
    flush(onu_);
    flush(dns_);
    flush(udp_);
    flush(pppoe_);
}

void RawFileManager::shutdown() {
    flushAll();
    auto close = [](WriterSlot& slot) {
        std::lock_guard<std::mutex> lk(slot.mu);
        slot.writer->close();
    };
    close(http_);
    close(tcp_);
    close(radius_);
    close(onu_);
    close(dns_);
    close(udp_);
    close(pppoe_);
}
