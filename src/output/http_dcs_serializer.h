#pragma once
#include "../record/http_record.h"
#include <cstdio>
#include <cstring>

// ─────────────────────────────────────────────────────────
// 将 HttpRecord 序列化为 Tab 分隔的 DCS 行
//
// 输出规范（来自示例文件）：
//   - 整数直接输出十进制
//   - double 保留6位小数
//   - 字符串：空值输出 NONE，含Tab/换行的字段需转义
//   - 字段间 \t 分隔，行尾 \n（由DcsWriter添加）
// ─────────────────────────────────────────────────────────
class HttpDcsSerializer
{
public:
	// 序列化到 buf，返回写入的字节数（不含'\0'）
	// buf_size 建议 >= 4096
	static size_t serialize(const HttpRecord &r,
							char *buf,
							size_t buf_size);

private:
	// 安全追加字符串字段（空值输出NONE，内部Tab替换为空格）
	static inline size_t appendStr(char *buf, size_t pos, size_t max,
								   const char *str)
	{
		const char *s = (str && str[0] != '\0') ? str : "NONE";
		size_t i = 0;
		while (s[i] && pos < max - 1)
		{
			// 防止字段内Tab破坏格式
			buf[pos++] = (s[i] == '\t' || s[i] == '\n') ? ' ' : s[i];
			++i;
		}
		return pos;
	}

	// 追加Tab分隔符
	static inline size_t tab(char *buf, size_t pos)
	{
		buf[pos] = '\t';
		return pos + 1;
	}
};