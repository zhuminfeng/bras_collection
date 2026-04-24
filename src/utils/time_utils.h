#pragma once
#include <cstdint>
#include <ctime>
#include <cstring>

namespace TimeUtils
{

	// 给定微秒时间戳，计算本小时整点的秒级时间戳
	inline uint32_t hourRoundTime(double start_time_sec)
	{
		uint64_t sec = (uint64_t)start_time_sec;
		return (uint32_t)(sec - sec % 3600);
	}

	// 给定微秒时间戳，计算本分钟整分的秒级时间戳
	inline uint32_t minRoundTime(double start_time_sec)
	{
		uint64_t sec = (uint64_t)start_time_sec;
		return (uint32_t)(sec - sec % 60);
	}

	// 将纳秒时间戳转为秒（double，保留微秒精度）
	inline double nsToSec(uint64_t ns)
	{
		return (double)ns / 1e9;
	}

	// 生成文件名时间戳部分：YYYYMMDDTHHmmSS
	// 使用文件创建时刻（整分钟）
	inline void formatFileTimestamp(uint32_t min_round_sec,
									char *buf, size_t buf_len)
	{
		time_t t = (time_t)min_round_sec;
		struct tm tm_info{};
		localtime_r(&t, &tm_info);
		strftime(buf, buf_len, "%Y%m%dT%H%M%S", &tm_info);
	}

} // namespace TimeUtils