#include "http_session.h"
#include <cstring>
#include <cstdio>
#include <cctype>
#include <algorithm>

// ─────────────────────────────────────────────────────────
// 通用：从原始数据流提取完整行（支持跨包）
// ─────────────────────────────────────────────────────────
template<typename OnLineFn>
uint32_t HttpSession::extractLines(char*       line_buf,
                                    uint32_t&   line_len,
                                    uint32_t    line_buf_size,
                                    const char* data,
                                    uint32_t    len,
                                    OnLineFn&&  on_line)
{
    uint32_t consumed = 0;

    while (consumed < len) {
        // 在 data[consumed..len) 中找 \n
        const char* p     = data + consumed;
        uint32_t    remain= len - consumed;
        const char* lf    = (const char*)memchr(p, '\n', remain);

        if (!lf) {
            // 没有找到 \n：把剩余数据追加到 line_buf
            uint32_t copy = std::min(remain,
                                     line_buf_size - line_len - 1);
            memcpy(line_buf + line_len, p, copy);
            line_len += copy;
            line_buf[line_len] = '\0';
            consumed = len;
            break;
        }

        // 找到 \n：拼装完整行
        uint32_t seg_len = (uint32_t)(lf - p); // 不含 \n

        uint32_t copy = std::min(seg_len,
                                  line_buf_size - line_len - 1);
        memcpy(line_buf + line_len, p, copy);
        line_len += copy;
        line_buf[line_len] = '\0';

        // 去掉末尾 \r
        if (line_len > 0 && line_buf[line_len - 1] == '\r') {
            line_buf[--line_len] = '\0';
        }

        // 回调处理这一行
        on_line(line_buf, line_len);

        // 重置 line_buf
        line_len = 0;
        line_buf[0] = '\0';

        consumed += seg_len + 1; // 跳过 \n
    }

    return consumed;
}

// ─────────────────────────────────────────────────────────
// 上行数据处理（HTTP 请求解析）
// ─────────────────────────────────────────────────────────
void HttpSession::onUpstreamData(const uint8_t* data,
                                  uint32_t       len,
                                  uint64_t       ts_us)
{
    if (!data || len == 0) return;

    // 记录请求时间（第一次收到上行数据）
    if (req_ts_us == 0) req_ts_us = ts_us;

    const char* cdata = (const char*)data;

    // ── body 阶段：直接追加 ───────────────────────────────
    if (req.header_done) {
        uint32_t copy = std::min(len,
            HttpRequest::MAX_BODY - req.body_len);
        if (copy > 0) {
            memcpy(req.body + req.body_len, cdata, copy);
            req.body_len += copy;
            req.body[req.body_len] = '\0';
        }
        return;
    }

    // ── header 阶段：逐行解析 ─────────────────────────────
    bool found_body_start = false;
    uint32_t body_offset  = 0;

    extractLines(
        req.line_buf, req.line_len,
        HttpRequest::LINE_BUF_SIZE,
        cdata, len,
        [&](const char* line, uint32_t llen) {
            if (found_body_start) return;

            if (req.state == HttpReqState::IDLE ||
                req.state == HttpReqState::REQUEST_LINE)
            {
                if (llen > 0) {
                    parseRequestLine(line, llen);
                    req.state = HttpReqState::HEADERS;
                }
                return;
            }

            if (req.state == HttpReqState::HEADERS) {
                if (llen == 0) {
                    // 空行 → header 结束
                    req.header_done  = true;
                    req.state        = HttpReqState::BODY;
                    found_body_start = true;
                    return;
                }
                parseRequestHeader(line, llen);
            }
        });

    // ── 如果header刚解析完，提取body部分 ─────────────────
    if (req.header_done) {
        // 在原始数据中找 \r\n\r\n
        const char* header_end = (const char*)
            memmem(cdata, len, "\r\n\r\n", 4);
        if (header_end) {
            body_offset = (uint32_t)(header_end - cdata) + 4;
            if (body_offset < len) {
                uint32_t body_remain = len - body_offset;
                uint32_t copy = std::min(body_remain,
                    HttpRequest::MAX_BODY - req.body_len);
                memcpy(req.body + req.body_len,
                       cdata + body_offset, copy);
                req.body_len += copy;
                req.body[req.body_len] = '\0';
            }
        }
    }
}

// ─────────────────────────────────────────────────────────
// 下行数据处理（HTTP 响应解析）
// ─────────────────────────────────────────────────────────
void HttpSession::onDownstreamData(const uint8_t* data,
                                    uint32_t       len,
                                    uint64_t       ts_us)
{
    if (!data || len == 0) return;

    // 记录响应时间（第一次收到下行数据）
    if (rsp_ts_us == 0) {
        rsp_ts_us = ts_us;
        if (req_ts_us > 0 && rsp_ts_us > req_ts_us) {
            response_interval_ms = (uint32_t)(
                (rsp_ts_us - req_ts_us) / 1000);
        }
    }

    // 响应 header 已解析完，不再处理
    if (rsp.header_done) return;

    const char* cdata = (const char*)data;

    extractLines(
        rsp.line_buf, rsp.line_len,
        HttpResponse::LINE_BUF_SIZE,
        cdata, len,
        [&](const char* line, uint32_t llen) {
            if (rsp.header_done) return;

            if (rsp.state == HttpRspState::IDLE ||
                rsp.state == HttpRspState::STATUS_LINE)
            {
                if (llen > 0) {
                    parseStatusLine(line, llen);
                    rsp.state = HttpRspState::HEADERS;
                }
                return;
            }

            if (rsp.state == HttpRspState::HEADERS) {
                if (llen == 0) {
                    rsp.header_done = true;
                    rsp.state       = HttpRspState::BODY;
                    return;
                }
                parseResponseHeader(line, llen);
            }
        });
}

// ─────────────────────────────────────────────────────────
// 解析请求行："GET /path HTTP/1.1"
// ─────────────────────────────────────────────────────────
void HttpSession::parseRequestLine(const char* line, uint32_t len) {
    // 找第一个空格（方法结束）
    const char* p   = line;
    const char* end = line + len;
    const char* sp1 = (const char*)memchr(p, ' ', len);
    if (!sp1) return;

    // 方法
    req.method = parseMethod(p, (uint32_t)(sp1 - p));

    // URL：从sp1+1到下一个空格
    const char* url_start = sp1 + 1;
    if (url_start >= end) return;
    const char* sp2 = (const char*)memchr(url_start, ' ',
                                           end - url_start);
    const char* url_end = sp2 ? sp2 : end;

    uint32_t url_len = (uint32_t)(url_end - url_start);
    uint32_t copy    = std::min(url_len, (uint32_t)767);
    memcpy(req.url, url_start, copy);
    req.url[copy] = '\0';
}

// ─────────────────────────────────────────────────────────
// 解析请求头："Header-Name: value"
// ─────────────────────────────────────────────────────────
void HttpSession::parseRequestHeader(const char* line, uint32_t len) {
    // 找 ':'
    const char* colon = (const char*)memchr(line, ':', len);
    if (!colon) return;

    uint32_t name_len = (uint32_t)(colon - line);
    const char* val   = colon + 1;
    // 跳过空格
    while (val < line + len && (*val == ' ' || *val == '\t'))
        ++val;
    uint32_t val_len = (uint32_t)(line + len - val);

    // 大小写不敏感匹配头名称
    if (name_len == 4 && iequals(line, "host", 4)) {
        uint32_t copy = std::min(val_len, (uint32_t)255);
        memcpy(req.host, val, copy);
        req.host[copy] = '\0';

    } else if (name_len == 10 &&
               iequals(line, "user-agent", 10)) {
        uint32_t copy = std::min(val_len, (uint32_t)255);
        memcpy(req.user_agent, val, copy);
        req.user_agent[copy] = '\0';

    } else if (name_len == 12 &&
               iequals(line, "content-type", 12)) {
        // 只取分号前的部分（去掉 "; charset=utf-8"）
        const char* semi = (const char*)memchr(val, ';', val_len);
        uint32_t ct_len  = semi ? (uint32_t)(semi - val) : val_len;
        // 去尾部空格
        while (ct_len > 0 && val[ct_len - 1] == ' ') --ct_len;
        uint32_t copy = std::min(ct_len, (uint32_t)255);
        memcpy(req.content_type, val, copy);
        req.content_type[copy] = '\0';

    } else if (name_len == 14 &&
               iequals(line, "content-length", 14)) {
        req.content_length = (uint32_t)strtoul(val, nullptr, 10);
    }
}

// ─────────────────────────────────────────────────────────
// 解析响应行："HTTP/1.1 200 OK"
// ─────────────────────────────────────────────────────────
void HttpSession::parseStatusLine(const char* line, uint32_t len) {
    // 找第一个空格
    const char* sp = (const char*)memchr(line, ' ', len);
    if (!sp) return;

    const char* code_start = sp + 1;
    uint32_t    remain     = (uint32_t)(line + len - code_start);
    if (remain < 3) return;

    rsp.status_code = (uint16_t)strtoul(code_start, nullptr, 10);
}

// ─────────────────────────────────────────────────────────
// 解析响应头
// ─────────────────────────────────────────────────────────
void HttpSession::parseResponseHeader(const char* line, uint32_t len) {
    const char* colon = (const char*)memchr(line, ':', len);
    if (!colon) return;

    uint32_t name_len = (uint32_t)(colon - line);
    const char* val   = colon + 1;
    while (val < line + len && (*val == ' ' || *val == '\t'))
        ++val;
    uint32_t val_len = (uint32_t)(line + len - val);

    if (name_len == 12 &&
        iequals(line, "content-type", 12)) {
        const char* semi = (const char*)memchr(val, ';', val_len);
        uint32_t ct_len  = semi ? (uint32_t)(semi - val) : val_len;
        while (ct_len > 0 && val[ct_len - 1] == ' ') --ct_len;
        uint32_t copy = std::min(ct_len, (uint32_t)255);
        memcpy(rsp.content_type, val, copy);
        rsp.content_type[copy] = '\0';
    }
}

// ─────────────────────────────────────────────────────────
// 解析 HTTP 方法字符串
// ─────────────────────────────────────────────────────────
HttpMethod HttpSession::parseMethod(const char* s, uint32_t len) {
    switch (len) {
    case 3:
        if (memcmp(s, "GET", 3)    == 0) return HttpMethod::GET;
        if (memcmp(s, "PUT", 3)    == 0) return HttpMethod::PUT;
        break;
    case 4:
        if (memcmp(s, "POST", 4)   == 0) return HttpMethod::POST;
        if (memcmp(s, "HEAD", 4)   == 0) return HttpMethod::HEAD;
        break;
    case 6:
        if (memcmp(s, "DELETE", 6) == 0) return HttpMethod::DELETE;
        break;
    case 7:
        if (memcmp(s, "OPTIONS", 7)== 0) return HttpMethod::OPTIONS;
        if (memcmp(s, "CONNECT", 7)== 0) return HttpMethod::CONNECT;
        break;
    default: break;
    }
    return HttpMethod::UNKNOWN;
}

// ─────────────────────────────────────────────────────────
// 去除首尾空白
// ─────────────────────────────────────────────────────────
uint32_t HttpSession::trim(char* s, uint32_t len) {
    if (len == 0) return 0;
    uint32_t start = 0;
    while (start < len &&
           (s[start] == ' ' || s[start] == '\t'))
        ++start;
    uint32_t end = len;
    while (end > start &&
           (s[end-1] == ' ' || s[end-1] == '\t'))
        --end;
    if (start > 0) memmove(s, s + start, end - start);
    uint32_t new_len = end - start;
    s[new_len] = '\0';
    return new_len;
}
