#pragma once
#include <cstdint>
#include <cstring>

// ─────────────────────────────────────────────────────────
// HTTP 请求方法
// ─────────────────────────────────────────────────────────
enum class HttpMethod : uint8_t {
    UNKNOWN = 0,
    GET     = 1,
    POST    = 2,
    HEAD    = 3,
    PUT     = 4,
    DELETE  = 5,
    OPTIONS = 6,
    CONNECT = 7,
};

// ─────────────────────────────────────────────────────────
// HTTP 请求解析状态
// ─────────────────────────────────────────────────────────
enum class HttpReqState : uint8_t {
    IDLE         = 0,   // 等待请求
    REQUEST_LINE = 1,   // 解析请求行
    HEADERS      = 2,   // 解析请求头
    BODY         = 3,   // 接收body
    DONE         = 4,   // 解析完成
};

// ─────────────────────────────────────────────────────────
// HTTP 响应解析状态
// ─────────────────────────────────────────────────────────
enum class HttpRspState : uint8_t {
    IDLE         = 0,
    STATUS_LINE  = 1,
    HEADERS      = 2,
    BODY         = 3,
    DONE         = 4,
};

// ─────────────────────────────────────────────────────────
// HTTP 请求数据
// ─────────────────────────────────────────────────────────
struct HttpRequest {
    HttpMethod  method              = HttpMethod::UNKNOWN;
    char        host[256]           = {};
    char        url[768]            = {};
    char        user_agent[256]     = {};
    char        content_type[256]   = {};

    // body 缓冲（ONU 软探针 JSON 上报用，最大 64KB）
    static constexpr uint32_t MAX_BODY = 65536;
    char        body[MAX_BODY]      = {};
    uint32_t    body_len            = 0;
    uint32_t    content_length      = 0;    // Content-Length 头的值

    // 解析状态
    HttpReqState state              = HttpReqState::IDLE;
    bool         header_done        = false;

    // 行缓冲（跨包时拼装不完整的行）
    static constexpr uint32_t LINE_BUF_SIZE = 1024;
    char        line_buf[LINE_BUF_SIZE] = {};
    uint32_t    line_len            = 0;

    void reset() { memset(this, 0, sizeof(*this)); }
};

// ─────────────────────────────────────────────────────────
// HTTP 响应数据
// ─────────────────────────────────────────────────────────
struct HttpResponse {
    uint16_t    status_code         = 0;
    char        content_type[256]   = {};

    // 解析状态
    HttpRspState state              = HttpRspState::IDLE;
    bool         header_done        = false;

    // 行缓冲
    static constexpr uint32_t LINE_BUF_SIZE = 512;
    char        line_buf[LINE_BUF_SIZE] = {};
    uint32_t    line_len            = 0;

    void reset() { memset(this, 0, sizeof(*this)); }
};

// ─────────────────────────────────────────────────────────
// HttpSession
//
// 职责：
//   - 解析 HTTP/1.x 请求头（方法/Host/URL/UA/Content-Type）
//   - 解析 HTTP/1.x 响应状态码
//   - 缓存 body（用于 ONU 软探针 JSON 解析）
//   - 记录响应间隔（请求时间→响应时间）
//
// 线程模型：
//   每个 FlowEntry 独占一个 HttpSession，单线程访问，无锁
//
// 限制：
//   - 只解析第一个 HTTP 事务（请求+响应）
//   - 不支持 HTTP/2（ALPN 协商后的 h2）
//   - chunked body 只做长度统计，不做完整重组
// ─────────────────────────────────────────────────────────
class HttpSession {
public:
    HttpRequest  req;
    HttpResponse rsp;

    uint64_t  req_ts_us           = 0;   // 请求第一个包时间
    uint64_t  rsp_ts_us           = 0;   // 响应第一个包时间
    uint32_t  response_interval_ms= 0;   // 响应间隔（ms）

    // ── 核心接口（WorkerThread 调用）─────────────────────
    // 上行数据（用户→服务器）：解析 HTTP 请求
    void onUpstreamData(const uint8_t* data,
                        uint32_t       len,
                        uint64_t       ts_us);

    // 下行数据（服务器→用户）：解析 HTTP 响应
    void onDownstreamData(const uint8_t* data,
                          uint32_t       len,
                          uint64_t       ts_us);

    void reset() {
        req.reset();
        rsp.reset();
        req_ts_us            = 0;
        rsp_ts_us            = 0;
        response_interval_ms = 0;
    }

private:
    // ── 请求行解析 ────────────────────────────────────────
    // "GET /index.html HTTP/1.1"
    void parseRequestLine(const char* line, uint32_t len);

    // ── 请求头逐行解析 ────────────────────────────────────
    // "Host: www.example.com"
    void parseRequestHeader(const char* line, uint32_t len);

    // ── 响应行解析 ────────────────────────────────────────
    // "HTTP/1.1 200 OK"
    void parseStatusLine(const char* line, uint32_t len);

    // ── 响应头逐行解析 ────────────────────────────────────
    void parseResponseHeader(const char* line, uint32_t len);

    // ── 通用：从原始数据流提取行（支持跨包）──────────────
    // 将 data[0..len) 按 \r\n 分行，逐行调用 on_line()
    // 返回已消费的字节数（剩余的存入 line_buf）
    template<typename OnLineFn>
    uint32_t extractLines(char*       line_buf,
                          uint32_t&   line_len,
                          uint32_t    line_buf_size,
                          const char* data,
                          uint32_t    len,
                          OnLineFn&&  on_line);

    // ── 工具 ──────────────────────────────────────────────
    // 解析 HTTP 方法字符串
    static HttpMethod parseMethod(const char* s, uint32_t len);

    // 大小写不敏感字符串比较（前 n 字节）
    static bool iequals(const char* a, const char* b, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            if (tolower((uint8_t)a[i]) != tolower((uint8_t)b[i]))
                return false;
        }
        return true;
    }

    // 去除字符串首尾空白（in-place，返回新长度）
    static uint32_t trim(char* s, uint32_t len);
};
