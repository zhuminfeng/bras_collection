#include "logger.h"
#include <filesystem>
#include <vector>

std::shared_ptr<spdlog::logger> Logger::logger_;

void Logger::init(const std::string &log_dir,
				  size_t max_mb,
				  size_t max_files)
{
	std::filesystem::create_directories(log_dir);

	auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
	console_sink->set_level(spdlog::level::info);

	auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
		log_dir + "/collector.log",
		max_mb * 1024 * 1024,
		max_files);
	file_sink->set_level(spdlog::level::debug);

	logger_ = std::make_shared<spdlog::logger>(
		"collector",
		spdlog::sinks_init_list{console_sink, file_sink});
	logger_->set_level(spdlog::level::debug);
	logger_->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v");
	logger_->flush_on(spdlog::level::warn);

	spdlog::set_default_logger(logger_);
	spdlog::info("Logger initialized, log_dir={}", log_dir);
}

void Logger::setLevel(spdlog::level::level_enum lv)
{
	if (logger_)
		logger_->set_level(lv);
	spdlog::set_level(lv);
}

std::shared_ptr<spdlog::logger> Logger::get()
{
	return logger_;
}