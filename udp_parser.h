#pragma once
#include "protocol_layer.h"
#include <string>

class UdpParser : public ProtocolLayer {
public:
    // 构造函数，接收 UDP 数据包的原始数据、长度、源 IP 和目的 IP
    explicit UdpParser(const uint8_t* data, size_t length, const IPv4Address& src_ip, const IPv4Address& dst_ip);

    // 实现基类的纯虚函数，返回协议类型为 UDP
    ProtocolType type() const noexcept override {
        return ProtocolType::UDP;
    }

    // 基类方法重构
    std::string summary() const noexcept override;
    const uint8_t* payload() const noexcept override {
        return payload_ptr_;
    }
    size_t payload_length() const noexcept override {
        return payload_len_;
    }

    // 获取源端口号
    uint16_t source_port() const;

    // 获取目的端口号
    uint16_t destination_port() const;

    // 获取 UDP 数据包的总长度（头部 + 数据）
    uint16_t total_length() const;

    // 获取 UDP 校验和
    uint16_t checksum() const;

    // 验证校验和
    bool verify_checksum() const;

private:
    // 解析 UDP 头部信息
    void parse(const uint8_t* data, size_t length);

    // 源端口号
    uint16_t source_port_;
    // 目的端口号
    uint16_t destination_port_;
    // UDP 数据包的总长度
    uint16_t total_length_;
    // UDP 校验和
    uint16_t checksum_;
    // 源 IP 地址
    const IPv4Address& src_ip_;
    // 目的 IP 地址
    const IPv4Address& dst_ip_;
    // 有效负载指针
    const uint8_t* payload_ptr_;
    // 有效负载长度
    size_t payload_len_;
};
