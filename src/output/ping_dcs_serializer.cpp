#include "ping_dcs_serializer.h"
#include <cstdio>
#include <cstring>

size_t PingDcsSerializer::serialize(const PingRecord& r,
                                     char*             buf,
                                     size_t            sz)
{
    // start_time / end_time：双精度浮点，精确到微秒
    // 示例文件中显示为整数是因为微秒部分恰好为0
    int n = snprintf(buf, sz,
        // 1~4  时间
        "%u\t%u\t%.6f\t%.6f\t"
        // 5~7  MAC + 账号
        "%lu\t%lu\t%s\t"
        // 8~11 IP + 域名
        "%u\t%u\t%u\t%s\t"
        // 12~15 统计
        "%u\t%u\t%u\t%u",

        r.hour_round_time,
        r.min_round_time,
        r.start_time,
        r.end_time,

        (unsigned long)r.user_mac_addr,
        (unsigned long)r.bras_mac_addr,
        r.user_account[0] ? r.user_account : "",

        r.user_ip,
        r.server_ip,
        r.host_hash,
        r.host_name[0] ? r.host_name : "",

        (unsigned)r.request_count,
        (unsigned)r.response_count,
        r.total_duration,
        (unsigned)r.payload_size
    );

    return (n > 0 && (size_t)n < sz) ? (size_t)n : 0;
}
