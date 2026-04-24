#pragma once
#include <cstring>
#include <regex>
#include <string>
#include <vector>

struct CpeInfo
{
	char model[256] = "NONE";
	char version[32] = "NONE";
};

// ─────────────────────────────────────────────────────────
// 从User-Agent提取CPE型号和版本
// 规则库可从配置文件加载，此处内置常见规则
// ─────────────────────────────────────────────────────────
class CpeDetector
{
public:
	CpeDetector();

	// 解析UA字符串，输出CPE信息
	CpeInfo detect(const char *user_agent) const;

private:
	struct Rule
	{
		std::regex pattern;
		int model_group;		  // 捕获组索引
		int version_group;		  // 0表示无版本
		std::string model_prefix; // 型号前缀（可选）
	};

	std::vector<Rule> rules_;

	void addRule(const char *pattern,
				 int model_group,
				 int version_group = 0,
				 const char *prefix = "");
};