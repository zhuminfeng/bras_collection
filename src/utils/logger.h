#pragma once
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <string>
#include <memory>

class Logger
{
public:
	// 初始化：同时输出到控制台和滚动文件
	// log_dir: 日志目录，max_mb: 单文件最大MB，max_files: 保留文件数
	static void init(const std::string &log_dir = "./logs",
					 size_t max_mb = 100,
					 size_t max_files = 10);

	// 动态调整日志级别
	static void setLevel(spdlog::level::level_enum lv);

	// 获取主logger（一般不直接使用，用spdlog::info等宏）
	static std::shared_ptr<spdlog::logger> get();

private:
	static std::shared_ptr<spdlog::logger> logger_;
};

// 便捷宏（转发给spdlog）
#define LOG_TRACE(...) spdlog::trace(__VA_ARGS__)
#define LOG_DEBUG(...) spdlog::debug(__VA_ARGS__)
#define LOG_INFO(...) spdlog::info(__VA_ARGS__)
#define LOG_WARN(...) spdlog::warn(__VA_ARGS__)
#define LOG_ERROR(...) spdlog::error(__VA_ARGS__)
#define LOG_CRITICAL(...) spdlog::critical(__VA_ARGS__)