#pragma once
#include <cstdint>
#include <cstring>
#include <shared_mutex>
#include <unordered_map>

// ─────────────────────────────────────────────────────────
// Radius线程写入，Worker线程只读
// 用IP查账号/MAC，使用读写锁
// ─────────────────────────────────────────────────────────
struct UserSession
{
	char user_account[256];
	uint64_t user_mac; // 用户拨号设备MAC
	uint64_t bras_mac; // BRAS MAC
	uint32_t framed_ip;
	uint64_t online_time; // 上线时间(ms)
	bool online;
};

class RadiusSessionTable
{
public:
	static RadiusSessionTable &instance()
	{
		static RadiusSessionTable inst;
		return inst;
	}

	// Radius线程：用户上线
	void userOnline(uint32_t ip, const UserSession &s)
	{
		std::unique_lock lk(mu_);
		table_[ip] = s;
	}

	// Radius线程：用户下线
	void userOffline(uint32_t ip)
	{
		std::unique_lock lk(mu_);
		table_.erase(ip);
	}

	// Worker线程：查询（高频，shared_lock）
	bool lookup(uint32_t ip, UserSession &out) const
	{
		std::shared_lock lk(mu_);
		auto it = table_.find(ip);
		if (it == table_.end())
			return false;
		out = it->second;
		return true;
	}

private:
	RadiusSessionTable() = default;
	mutable std::shared_mutex mu_;
	std::unordered_map<uint32_t, UserSession> table_;
};