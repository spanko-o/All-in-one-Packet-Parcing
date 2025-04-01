#pragma once
#include "protocol_layer.h"
#include <string>

class EthernetParser : public ProtocolLayer {
public:
    explicit EthernetParser(const uint8_t* data, size_t length);

    // ProtocolLayer 接口实现
    ProtocolType type() const noexcept override {
        return ProtocolType::ETHERNET;
    }
    std::string summary() const noexcept override;

    const uint8_t* payload() const noexcept override {
        return payload_ptr_;
    }
    size_t payload_length() const noexcept override {
        return payload_len_;
    }

    // 以太网特有方法
    const MacAddress& source_mac() const noexcept {
        return src_mac_;
    }
    const MacAddress& destination_mac() const noexcept {
        return dst_mac_;
    }
    uint16_t ether_type() const noexcept {
        return ether_type_;
    }

private:
    void parse();

    MacAddress src_mac_;
    MacAddress dst_mac_;
    uint16_t ether_type_;
};