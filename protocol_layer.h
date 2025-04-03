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
	ProtocolLayer(const uint8_t* data, size_t length)
		: raw_data_(data),
		data_length_(length),
		payload_ptr_(nullptr),
		payload_len_(0) {}

	virtual ~ProtocolLayer() = default;

	virtual ProtocolType type() const noexcept = 0;

	virtual std::string summary() const noexcept = 0;

	virtual const uint8_t* payload() const noexcept = 0;

	virtual size_t payload_length() const noexcept = 0;

	const uint8_t* raw_data() const noexcept {
		return raw_data_;
	}
	size_t data_length() const noexcept {
		return data_length_;
	}

protected:
	const uint8_t* raw_data_;      // ԭʼ����ָ��
	size_t data_length_;           // �����ܳ���
	const uint8_t* payload_ptr_;
	size_t payload_len_;
};