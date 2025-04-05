#pragma once
#include "protocol_layer.h"
#include <string>

class UdpParser : public ProtocolLayer {
public:
    explicit UdpParser(const uint8_t* data, size_t length, const IPv4Address& src_ip, const IPv4Address& dst_ip);

    ProtocolType type() const noexcept override {
        return ProtocolType::UDP;
    }

    std::string summary() const noexcept override;
    const uint8_t* payload() const noexcept override {
        return payload_ptr_;
    }
    size_t payload_length() const noexcept override {
        return payload_len_;
    }

    uint16_t source_port() const;

    uint16_t destination_port() const;

    uint16_t total_length() const;

    uint16_t checksum() const;

    bool verify_checksum() const;

private:
    void parse();

    uint16_t calculate_udp_checksum(const uint8_t* data, size_t length, const IPv4Address& src_ip, const IPv4Address& dst_ip) const;

    uint16_t source_port_;
    uint16_t destination_port_;
    uint16_t total_length_;
    uint16_t checksum_;

    const IPv4Address& src_ip_;
    const IPv4Address& dst_ip_;
    const uint8_t* payload_ptr_;
    size_t payload_len_;
};
