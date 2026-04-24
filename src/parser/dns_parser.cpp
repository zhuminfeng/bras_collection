#include "dns_parser.h"
#include <IPv4Layer.h>
#include <UdpLayer.h>
#include <cstring>
#include <cstdio>

bool DnsParser::parse(const pcpp::Packet &pkt,
					  uint64_t ts_us,
					  bool is_response,
					  DnsRecord &out)
{
	memset(&out, 0, sizeof(out));
	out.query_time = ts_us;

	auto *ip = pkt.getLayerOfType<pcpp::IPv4Layer>();
	if (!ip)
		return false;

	// 方向：查询包 src=用户，dst=DNS服务器
	if (!is_response)
	{
		out.user_ip = ntohl(ip->getSrcIPv4Address().toInt());
		out.dns_server_ip = ntohl(ip->getDstIPv4Address().toInt());
	}
	else
	{
		out.user_ip = ntohl(ip->getDstIPv4Address().toInt());
		out.dns_server_ip = ntohl(ip->getSrcIPv4Address().toInt());
	}

	auto *dns = pkt.getLayerOfType<pcpp::DnsLayer>();
	if (!dns)
		return false;

	// ── 查询字段 ──────────────────────────────
	auto *query = dns->getFirstQuery();
	if (query)
	{
		strncpy(out.query_name,
				query->getName().c_str(),
				sizeof(out.query_name) - 1);
		out.query_type = (uint16_t)query->getDnsType();
	}

	// ── 响应字段 ──────────────────────────────
	if (is_response)
	{
		out.result_code = (uint8_t)(dns->getDnsHeader()->responseCode & 0x0F);
		serializeAnswers(dns, out.answers, sizeof(out.answers));
	}

	return true;
}

void DnsParser::serializeAnswers(pcpp::DnsLayer *dns,
								 char *buf, size_t buf_size)
{
	size_t pos = 0;
	auto *ans = dns->getFirstAnswer();
	while (ans && pos < buf_size - 2)
	{
		if (pos > 0)
			buf[pos++] = ',';
		std::string val = ans->getData()->toString();
		size_t copy = std::min(val.size(), buf_size - pos - 1);
		memcpy(buf + pos, val.c_str(), copy);
		pos += copy;
		ans = dns->getNextAnswer(ans);
	}
	buf[pos] = '\0';
}

const char *DnsParser::queryTypeStr(uint16_t type)
{
	switch (type)
	{
	case 1:
		return "A";
	case 28:
		return "AAAA";
	case 5:
		return "CNAME";
	case 15:
		return "MX";
	case 6:
		return "SOA";
	default:
		return "OTHER";
	}
}