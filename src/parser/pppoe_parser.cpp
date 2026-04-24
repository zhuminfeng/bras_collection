#include "pppoe_parser.h"
#include <PPPoELayer.h>
#include <EthLayer.h>
#include <cstring>

bool PPPoEParser::parse(const pcpp::Packet &pkt,
						uint64_t ts_us,
						PPPoERecord &out)
{
	memset(&out, 0, sizeof(out));
	out.event_time = ts_us;

	// 以太层 → 提取MAC
	auto *eth = pkt.getLayerOfType<pcpp::EthLayer>();
	if (!eth)
		return false;
	out.client_mac = mac2u64(eth->getSourceMac().getRawData());
	out.server_mac = mac2u64(eth->getDestMac().getRawData());

	// PPPoE Discovery层
	auto *disc = pkt.getLayerOfType<pcpp::PPPoEDiscoveryLayer>();
	if (disc)
	{
		uint8_t code = disc->getPPPoEHeader()->code;
		switch (code)
		{
		case 0x09:
			out.event_type = (uint8_t)PPPoEEventType::PADI;
			break;
		case 0x07:
			out.event_type = (uint8_t)PPPoEEventType::PADO;
			break;
		case 0x19:
			out.event_type = (uint8_t)PPPoEEventType::PADR;
			break;
		case 0x65:
			out.event_type = (uint8_t)PPPoEEventType::PADS;
			break;
		case 0xa7:
			out.event_type = (uint8_t)PPPoEEventType::PADT;
			break;
		default:
			out.event_type = (uint8_t)PPPoEEventType::UNKNOWN;
			break;
		}
		out.session_id = rte_be_to_cpu_16(
			disc->getPPPoEHeader()->sessionId);

		// 提取Tag字段
		auto ac = extractTag(disc,
							 pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_AC_NAME);
		auto svc = extractTag(disc,
							  pcpp::PPPoEDiscoveryLayer::PPPOE_TAG_SVC_NAME);
		strncpy(out.ac_name, ac.c_str(), sizeof(out.ac_name) - 1);
		strncpy(out.service_name, svc.c_str(), sizeof(out.service_name) - 1);
		return true;
	}

	// PPPoE Session层
	auto *sess = pkt.getLayerOfType<pcpp::PPPoESessionLayer>();
	if (sess)
	{
		out.event_type = (uint8_t)PPPoEEventType::SESSION;
		out.session_id = rte_be_to_cpu_16(
			sess->getPPPoEHeader()->sessionId);
		return true;
	}

	return false;
}

std::string PPPoEParser::extractTag(
	pcpp::PPPoEDiscoveryLayer *layer,
	pcpp::PPPoEDiscoveryLayer::PPPoETagTypes type)
{
	auto *tag = layer->getTag(type);
	if (!tag)
		return {};
	uint16_t len = tag->getTagLength();
	if (len == 0)
		return {};
	return std::string(reinterpret_cast<const char *>(tag->getTagData()),
					   len);
}