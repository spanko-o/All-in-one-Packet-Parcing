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

//MAC��ַ�ṹ6�ֽ�
struct MacAddress {
	uint8_t bytes[6];
};

//IPv4��ַ�ṹ4�ֽ�
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