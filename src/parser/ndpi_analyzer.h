#pragma once
extern "C"
{
#include <ndpi_main.h>
#include <ndpi_typedefs.h>
}
#include <cstdint>
#include <string>
#include <memory>
#include <unordered_map>
#include "../record/record_types.h"

// 流状态（每个TCP/UDP五元组一个）
struct NdpiFlowState
{
	ndpi_flow_struct *ndpi_flow = nullptr;
	ndpi_id_struct *src_id = nullptr;
	ndpi_id_struct *dst_id = nullptr;
	ndpi_protocol detected_proto{};
	uint32_t pkt_count = 0;
	bool detection_done = false;
};

class NdpiAnalyzer
{
public:
	NdpiAnalyzer();
	~NdpiAnalyzer();

	// 对单个数据包运行DPI检测
	// 返回是否检测完成（达到最大包数或已识别）
	bool processPacket(
		NdpiFlowState &flow_state,
		const uint8_t *pkt_data, // IP层开始
		uint32_t pkt_len,
		uint64_t timestamp_ms,
		bool is_upstream);

	// 获取协议名称
	std::string getProtoName(const ndpi_protocol &proto) const;

	// 获取业务分类（游戏/视频/直播/其他）
	uint8_t getTrafficType(const ndpi_protocol &proto) const;

	// 创建新流状态
	NdpiFlowState createFlowState();

	// 释放流状态内存
	void releaseFlowState(NdpiFlowState &state);

	// 最大检测包数（超过后停止继续检测节省CPU）
	static constexpr uint32_t MAX_DETECT_PKTS = 16;

private:
	struct ndpi_detection_module_struct *ndpi_module_ = nullptr;
	uint32_t detection_bitmask_ = 0;
};