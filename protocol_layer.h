#pragma once

#include <memory>
#include <vector>
#include <string>
#include <cstdint>

enum class ProtocolType {
	ETHERNET,
	IPv4,
	UDP,
	DNS,
	UNKOWN
};

//MAC地址结构6字节
struct MacAddress {
	uint8_t bytes[6];
};

//IPv4地址结构4字节
struct IPv4Address {
	uint8_t bytes[4];
};

class ProtocolLayer {
public:
	virtual ~ProtocolLayer() = default;

	virtual ProtocolType type() const noexcept = 0;

	virtual std::string summary() const noexcept = 0;

	virtual const uint8_t* payload() const noexcept = 0;

	virtual size_t payload_length() const noexcept = 0;
};