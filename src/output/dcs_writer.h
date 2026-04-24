#pragma once
#include <cstdio>
#include <cstdint>
#include <string>
#include <functional>
#include <stdexcept>

// ─────────────────────────────────────────────────────────
// DCS文件写出引擎
// 特性：
//   - 大缓冲区(4MB)批量fwrite，减少系统调用
//   - 每分钟轮转文件（由外部调用 rotate()）
//   - 线程不安全（每个OutputThread独占一组writer）
// ─────────────────────────────────────────────────────────
class DcsWriter
{
public:
	static constexpr size_t WRITE_BUFFER_SIZE = 4 * 1024 * 1024; // 4MB

	// prefix: "http" / "tcp" / "radius" 等
	// dir: 输出目录，如 "/data/raw"
	// collector_id: 采集机编号（两位，如 "01"）
	DcsWriter(const std::string &prefix,
			  const std::string &dir,
			  const std::string &collector_id);
	~DcsWriter();

	// 写入一行（已序列化好的tab分隔字符串，不含'\n'）
	void writeLine(const char *line, size_t len);

	// 轮转文件（每分钟调用一次）
	// min_round_sec: 新文件对应的整分钟时间戳
	void rotate(uint32_t min_round_sec);

	// 强制刷盘
	void flush();

	// 关闭当前文件
	void close();

	// 获取当前文件路径（用于监控）
	const std::string &currentPath() const { return current_path_; }

	// 当前文件已写行数
	uint64_t lineCount() const { return line_count_; }

	// 禁止拷贝
	DcsWriter(const DcsWriter &) = delete;
	DcsWriter &operator=(const DcsWriter &) = delete;

private:
	void openNewFile(uint32_t min_round_sec);

	std::string prefix_;
	std::string dir_;
	std::string collector_id_;
	std::string current_path_;

	FILE *fp_ = nullptr;
	char *write_buf_ = nullptr; // 用户态写缓冲
	size_t buf_pos_ = 0;
	uint64_t line_count_ = 0;
	uint32_t cur_min_ = 0; // 当前文件对应的整分时间戳
};