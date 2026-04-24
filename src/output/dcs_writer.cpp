#include "dcs_writer.h"
#include "../utils/time_utils.h"
#include <spdlog/spdlog.h>
#include <sys/stat.h>
#include <cerrno>
#include <cstring>
#include <filesystem>

DcsWriter::DcsWriter(const std::string &prefix,
					 const std::string &dir,
					 const std::string &collector_id)
	: prefix_(prefix), dir_(dir), collector_id_(collector_id)
{
	// 确保输出目录存在
	std::filesystem::create_directories(dir_);

	// 分配用户态写缓冲（避免每行都触发系统调用）
	write_buf_ = new char[WRITE_BUFFER_SIZE];
}

DcsWriter::~DcsWriter()
{
	flush();
	close();
	delete[] write_buf_;
}

void DcsWriter::writeLine(const char *line, size_t len)
{
	// +1 for '\n'
	size_t total = len + 1;

	// 缓冲区不足时先刷盘
	if (buf_pos_ + total > WRITE_BUFFER_SIZE)
	{
		flush();
	}

	// 若单行超过缓冲区（极端情况），直接写
	if (total > WRITE_BUFFER_SIZE)
	{
		if (fp_)
		{
			fwrite(line, 1, len, fp_);
			fputc('\n', fp_);
		}
	}
	else
	{
		memcpy(write_buf_ + buf_pos_, line, len);
		buf_pos_ += len;
		write_buf_[buf_pos_++] = '\n';
	}

	++line_count_;
}

void DcsWriter::flush()
{
	if (fp_ && buf_pos_ > 0)
	{
		fwrite(write_buf_, 1, buf_pos_, fp_);
		buf_pos_ = 0;
		// 不调用fflush，让OS管理page cache刷盘
		// 如需保证落盘可加：fflush(fp_);
	}
}

void DcsWriter::close()
{
	if (fp_)
	{
		fclose(fp_);
		fp_ = nullptr;
		spdlog::info("[DcsWriter] closed: {} ({} lines)",
					 current_path_, line_count_);
	}
}

void DcsWriter::rotate(uint32_t min_round_sec)
{
	if (cur_min_ == min_round_sec)
		return; // 同一分钟不重复轮转

	flush();
	close();
	line_count_ = 0;
	openNewFile(min_round_sec);
}

void DcsWriter::openNewFile(uint32_t min_round_sec)
{
	cur_min_ = min_round_sec;

	// 生成时间戳字符串：YYYYMMDDTHHmmSS
	char ts_str[20];
	TimeUtils::formatFileTimestamp(min_round_sec, ts_str, sizeof(ts_str));

	// 文件名：{prefix}_{timestamp}{collector_id}.dcs
	// 示例：http_20210610T181207.dcs（collector_id=""）
	//       http_20210610T18120701.dcs（collector_id="01"）
	current_path_ = dir_ + "/" + prefix_ + "_" + ts_str + collector_id_ + ".dcs";

	fp_ = fopen(current_path_.c_str(), "wb");
	if (!fp_)
	{
		throw std::runtime_error(
			"DcsWriter: cannot open " + current_path_ + ": " + strerror(errno));
	}

	// 设置stdio缓冲为无缓冲（我们自己管缓冲）
	setvbuf(fp_, nullptr, _IONBF, 0);

	spdlog::info("[DcsWriter] opened: {}", current_path_);
}