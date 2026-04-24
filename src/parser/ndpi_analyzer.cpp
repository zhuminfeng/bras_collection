#include "ndpi_analyzer.h"
#include <ndpi_main.h>
#include <cstring>
#include <stdexcept>

NdpiAnalyzer::NdpiAnalyzer()
{
	ndpi_module_ = ndpi_init_detection_module(nullptr);
	if (!ndpi_module_)
	{
		throw std::runtime_error("ndpi_init_detection_module failed");
	}
	// 启用所有协议
	NDPI_BITMASK_SET_ALL(detection_bitmask_);
	ndpi_set_protocol_detection_bitmask2(ndpi_module_,
										 reinterpret_cast<NDPI_PROTOCOL_BITMASK *>(&detection_bitmask_));
	ndpi_finalize_initialization(ndpi_module_);
}

NdpiAnalyzer::~NdpiAnalyzer()
{
	if (ndpi_module_)
	{
		ndpi_exit_detection_module(ndpi_module_);
	}
}

NdpiFlowState NdpiAnalyzer::createFlowState()
{
	NdpiFlowState s{};
	s.ndpi_flow = (ndpi_flow_struct *)calloc(1, ndpi_flow_struct_size());
	s.src_id = (ndpi_id_struct *)calloc(1, ndpi_sizeof_id_struct());
	s.dst_id = (ndpi_id_struct *)calloc(1, ndpi_sizeof_id_struct());
	return s;
}

void NdpiAnalyzer::releaseFlowState(NdpiFlowState &state)
{
	if (state.ndpi_flow)
	{
		ndpi_free_flow(state.ndpi_flow);
		state.ndpi_flow = nullptr;
	}
	if (state.src_id)
	{
		free(state.src_id);
		state.src_id = nullptr;
	}
	if (state.dst_id)
	{
		free(state.dst_id);
		state.dst_id = nullptr;
	}
}

bool NdpiAnalyzer::processPacket(
	NdpiFlowState &fs,
	const uint8_t *pkt_data,
	uint32_t pkt_len,
	uint64_t timestamp_ms,
	bool is_upstream)
{
	if (fs.detection_done)
		return true;
	if (fs.pkt_count >= MAX_DETECT_PKTS)
	{
		// 强制完成，接受当前猜测结果
		fs.detected_proto = ndpi_detection_giveup(
			ndpi_module_, fs.ndpi_flow, 1, nullptr);
		fs.detection_done = true;
		return true;
	}

	fs.detected_proto = ndpi_detection_process_packet(
		ndpi_module_,
		fs.ndpi_flow,
		pkt_data,
		(unsigned short)pkt_len,
		timestamp_ms,
		is_upstream ? fs.src_id : fs.dst_id,
		is_upstream ? fs.dst_id : fs.src_id);

	++fs.pkt_count;

	// 当master_protocol有效时认为已识别
	if (fs.detected_proto.master_protocol != NDPI_PROTOCOL_UNKNOWN ||
		fs.detected_proto.app_protocol != NDPI_PROTOCOL_UNKNOWN)
	{
		fs.detection_done = true;
		return true;
	}
	return false;
}

std::string NdpiAnalyzer::getProtoName(const ndpi_protocol &proto) const
{
	char buf[64];
	ndpi_protocol2name(ndpi_module_, proto, buf, sizeof(buf));
	return std::string(buf);
}

uint8_t NdpiAnalyzer::getTrafficType(const ndpi_protocol &proto) const
{
	// 根据nDPI协议分类映射到业务类型
	// 0=其他 1=游戏 2=视频点播 3=直播
	uint16_t app = proto.app_protocol;

	// 游戏
	if (app == NDPI_PROTOCOL_STEAM ||
		app == NDPI_PROTOCOL_XBOX ||
		app == NDPI_PROTOCOL_PLAYSTATION)
		return 1;

	// 视频
	if (app == NDPI_PROTOCOL_YOUTUBE ||
		app == NDPI_PROTOCOL_NETFLIX ||
		app == NDPI_PROTOCOL_IQIYI ||
		app == NDPI_PROTOCOL_BILIBILI)
		return 2;

	// 直播
	if (app == NDPI_PROTOCOL_TWITCH ||
		app == NDPI_PROTOCOL_RTMP ||
		app == NDPI_PROTOCOL_RTSP)
		return 3;

	return 0;
}