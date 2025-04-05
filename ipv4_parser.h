#pragma once

#include "protocol_layer.h"
#include <string>

class IPv4Parser : public ProtocolLayer {
public:
    explicit IPv4Parser(const uint8_t* data, size_t length);

    ProtocolType type() const noexcept override {
        return ProtocolType::IPv4;
    }
    std::string summary() const noexcept override;
    const uint8_t* payload() const noexcept override {
        return payload_ptr_;
    }
    size_t payload_length() const noexcept override {
        return payload_len_;
    }

    // IPv4特有方法
    const IPv4Address& source_ip() const noexcept {
        return src_ip_;
    }
    const IPv4Address& destination_ip() const noexcept {
        return dst_ip_;
    }
    uint8_t protocol() const noexcept {
        return protocol_;
    }
    uint8_t time_to_live() const noexcept {
        return ttl_;
    }

private:
    void parse();

    IPv4Address src_ip_;
    IPv4Address dst_ip_;
    uint8_t protocol_;
    uint8_t ttl_;
    uint16_t total_length_;
};