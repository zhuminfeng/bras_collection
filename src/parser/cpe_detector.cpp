#include "cpe_detector.h"
#include <spdlog/spdlog.h>

CpeDetector::CpeDetector()
{
	// ── 常见Android应用/设备UA规则 ───────────────────────
	// 格式示例：
	//   aegon-android/4.29.0
	//   okhttp/3.12.1
	//   Dalvik/2.1.0 (Linux; U; Android 10; PDBM00 Build/QP1A)
	//   Mozilla/5.0 (Linux; Android 9; Redmi Note 7)
	//   com.xxx.app/1.0 (iPhone; iOS 14.0; Scale/3.00)

	// Android设备型号（Dalvik UA中）
	addRule(R"(Dalvik/[\d.]+ \(Linux; U; Android [\d.]+; ([A-Z0-9]+) Build/)",
			1, 0);

	// Mozilla Android
	addRule(R"(Mozilla/5\.0 \(Linux; Android [\d.]+; ([^;)]+)\))",
			1, 0);

	// iPhone/iPad
	addRule(R"((iPhone|iPad); iOS ([\d.]+))", 1, 2);

	// 常见APP/版本（app_name/version）
	addRule(R"(^([a-zA-Z][a-zA-Z0-9\-]+)/([\d.]+))", 1, 2);

	// ONU相关UA（定制）
	addRule(R"(TR069Client/([A-Z0-9\-]+)/([\d.]+))", 1, 2);
}

void CpeDetector::addRule(const char *pattern,
						  int model_group,
						  int version_group,
						  const char *prefix)
{
	try
	{
		rules_.push_back({std::regex(pattern, std::regex::icase | std::regex::optimize),
						  model_group,
						  version_group,
						  prefix ? prefix : ""});
	}
	catch (const std::regex_error &e)
	{
		spdlog::warn("CpeDetector: bad regex '{}': {}", pattern, e.what());
	}
}

CpeInfo CpeDetector::detect(const char *user_agent) const
{
	CpeInfo info{};
	if (!user_agent || !user_agent[0])
		return info;

	std::string ua(user_agent);
	std::smatch m;

	for (auto &rule : rules_)
	{
		if (std::regex_search(ua, m, rule.pattern))
		{
			// 型号
			if (rule.model_group > 0 &&
				rule.model_group < (int)m.size() &&
				m[rule.model_group].matched)
			{
				std::string model = rule.model_prefix +
									m[rule.model_group].str();
				strncpy(info.model, model.c_str(),
						sizeof(info.model) - 1);
			}
			// 版本
			if (rule.version_group > 0 &&
				rule.version_group < (int)m.size() &&
				m[rule.version_group].matched)
			{
				strncpy(info.version,
						m[rule.version_group].str().c_str(),
						sizeof(info.version) - 1);
			}
			return info;
		}
	}
	return info; // 未识别，保持 "NONE"
}