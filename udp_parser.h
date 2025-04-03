#pragma once
#include "protocol_layer.h"
#include <string>

class UdpParser : public ProtocolLayer {
public:
    // ���캯�������� UDP ���ݰ���ԭʼ���ݡ����ȡ�Դ IP ��Ŀ�� IP
    explicit UdpParser(const uint8_t* data, size_t length, const IPv4Address& src_ip, const IPv4Address& dst_ip);

    // ʵ�ֻ���Ĵ��麯��������Э������Ϊ UDP
    ProtocolType type() const noexcept override {
        return ProtocolType::UDP;
    }

    // ���෽���ع�
    std::string summary() const noexcept override;
    const uint8_t* payload() const noexcept override {
        return payload_ptr_;
    }
    size_t payload_length() const noexcept override {
        return payload_len_;
    }

    // ��ȡԴ�˿ں�
    uint16_t source_port() const;

    // ��ȡĿ�Ķ˿ں�
    uint16_t destination_port() const;

    // ��ȡ UDP ���ݰ����ܳ��ȣ�ͷ�� + ���ݣ�
    uint16_t total_length() const;

    // ��ȡ UDP У���
    uint16_t checksum() const;

    // ��֤У���
    bool verify_checksum() const;

private:
    // ���� UDP ͷ����Ϣ
    void parse(const uint8_t* data, size_t length);

    // Դ�˿ں�
    uint16_t source_port_;
    // Ŀ�Ķ˿ں�
    uint16_t destination_port_;
    // UDP ���ݰ����ܳ���
    uint16_t total_length_;
    // UDP У���
    uint16_t checksum_;
    // Դ IP ��ַ
    const IPv4Address& src_ip_;
    // Ŀ�� IP ��ַ
    const IPv4Address& dst_ip_;
    // ��Ч����ָ��
    const uint8_t* payload_ptr_;
    // ��Ч���س���
    size_t payload_len_;
};
