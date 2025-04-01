#include "ipv4_parser.h"
#include <stdexcept>
#include <iomanip>
#include <sstream>

// IPv4ͷ����С���ȣ���ѡ��ʱ��
constexpr size_t IPV4_MIN_HEADER_LEN = 20;

IPv4Parser::IPv4Parser(const uint8_t* data, size_t length)
    : raw_data_(data),
    data_length_(length),
    payload_ptr_(nullptr),
    payload_len_(0) {
    parse(data, length);
}

void IPv4Parser::parse(const uint8_t* data, size_t length) {
    // �������ȼ��
    if (length < IPV4_MIN_HEADER_LEN) {
        throw std::runtime_error("IPv4 header too short");
    }

    // �����汾��ͷ�����ȣ�ǰ4λ�ǰ汾����4λ��IHL��
    uint8_t version_ihl = data[0];
    uint8_t ihl = version_ihl & 0x0F;  // ͷ�����ȣ�32λ��Ϊ��λ��
    size_t header_bytes = ihl * 4;     // ת��Ϊ�ֽ���

    // ��֤ͷ������
    if (header_bytes < IPV4_MIN_HEADER_LEN || header_bytes > length) {
        throw std::runtime_error("Invalid IPv4 header length");
    }

    // �����ؼ��ֶ�
    total_length_ = (data[2] << 8) | data[3];  // �ܳ��ȣ������ֽ���
    ttl_ = data[8];
    protocol_ = data[9];

    // ����IP��ַ
    std::copy(data + 12, data + 16, src_ip_.bytes);
    std::copy(data + 16, data + 20, dst_ip_.bytes);

    // ����payload
    payload_ptr_ = data + header_bytes;
    payload_len_ = total_length_ - header_bytes;

    // ���ȶ�����֤
    if (payload_len_ > (length - header_bytes)) {
        payload_len_ = length - header_bytes;  // ����ʵ�ʲ��񳤶�
    }
}

std::string IPv4Parser::summary() const noexcept {
    auto ip_to_str = [](const IPv4Address& ip) {
        std::ostringstream oss;
        oss << static_cast<int>(ip.bytes[0]) << "."
            << static_cast<int>(ip.bytes[1]) << "."
            << static_cast<int>(ip.bytes[2]) << "."
            << static_cast<int>(ip.bytes[3]);
        return oss.str();
    };

    std::string protocol_str;
    switch (protocol_) {
    case 6:  protocol_str = "TCP"; break;
    case 17: protocol_str = "UDP"; break;
    case 1:  protocol_str = "ICMP"; break;
    default: protocol_str = "0x" + std::to_string(protocol_);
    }

    return "IPv4 [Src: " + ip_to_str(src_ip_) +
        ", Dst: " + ip_to_str(dst_ip_) +
        ", Proto: " + protocol_str +
        ", TTL: " + std::to_string(ttl_) + "]";
}