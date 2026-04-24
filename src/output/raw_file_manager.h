#pragma once

#include "dcs_writer.h"
#include "../record/record_types.h"
#include "../record/http_record.h"
#include <memory>
#include <mutex>
#include <string>

class RawFileManager {
public:
    RawFileManager(const std::string& raw_dir,
                   const std::string& collector_id);
    ~RawFileManager();

    // ── 各协议写入接口 ────────────────────────────────────
    void writeHttp  (const HttpRecord&        rec);
    void writeTcp   (const TcpSessionRecord&  rec);
    void writeRadius(const RadiusRecord&      rec);
    void writeOnu   (const OnuRecord&         rec);
    void writeDns   (const DnsRecord&         rec);
    void writeUdp   (const UdpStreamRecord&   rec);
    void writePPPoE (const PPPoERecord&       rec);

    // ── 文件轮转（OutputThread每分钟调用）────────────────
    void rotateIfNeeded(uint32_t min_round_sec);

    // ── 刷盘 / 停止 ───────────────────────────────────────
    void flushAll();
    void shutdown();

private:
    struct WriterSlot {
        std::unique_ptr<DcsWriter> writer;
        std::mutex                 mu;
        WriterSlot() = default;
        WriterSlot(const WriterSlot&)            = delete;
        WriterSlot& operator=(const WriterSlot&) = delete;
    };

    template<typename SerFn>
    void writeToSlot(WriterSlot& slot, SerFn&& serialize_fn);

    void initWriters(uint32_t min_round_sec);

    std::string raw_dir_;
    std::string collector_id_;
    uint32_t    last_min_ts_ = 0;

    WriterSlot  http_;
    WriterSlot  tcp_;
    WriterSlot  radius_;
    WriterSlot  onu_;
    WriterSlot  dns_;
    WriterSlot  udp_;
    WriterSlot  pppoe_;

    static constexpr size_t SER_BUF_SIZE = 4096;
};
