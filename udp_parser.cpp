#include <stdexcept>
#include <iomanip>
#include <sstream>
#include <vector>
#include <cstring>
#include "udp_parser.h"

constexpr size_t UDP_LEN = 8;

// ���� 16 λ������͵ĸ�������
uint16_t UdpParser::calculate_udp_checksum(const uint8_t* data, size_t length, const IPv4Address_new& src_ip, const IPv4Address_new& dst_ip) const {
    // ����α�ײ�
    uint8_t pseudo_header[12];
    memcpy(pseudo_header, src_ip.bytes, 4);
    memcpy(pseudo_header + 4, dst_ip.bytes, 4);
    pseudo_header[8] = 0;
    pseudo_header[9] = 17;  // UDP Э���
    pseudo_header[10] = (length >> 8) & 0xff;
    pseudo_header[11] = length & 0xff;

    // �ϲ�α�ײ���UDP �ײ�������
    std::vector<uint8_t> buffer;
    buffer.insert(buffer.end(), pseudo_header, pseudo_header + 12);
    buffer.insert(buffer.end(), data, data + length);

    uint32_t sum = 0;
    const uint16_t* ptr = reinterpret_cast<const uint16_t*>(buffer.data());
    size_t n = buffer.size() / 2;
    for (size_t i = 0; i < n; ++i) {
        sum += *ptr++;
    }
    if (buffer.size() % 2 == 1) {
        sum += static_cast<uint32_t>(buffer.back()) << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

UdpParser::UdpParser(const uint8_t* data, size_t length, const IPv4Address_new& src_ip, const IPv4Address_new& dst_ip)
    : ProtocolLayer(data, length), src_ip_(src_ip), dst_ip_(dst_ip), payload_ptr_(nullptr), payload_len_(0) {
    parse();
}

void UdpParser::parse() {
    const uint8_t* data = raw_data_;
    size_t length = data_length_;
    if (length < UDP_LEN) {
        throw std::runtime_error("UDP packet is too short to have a valid header.");
    }
    // ����Դ�˿�
    source_port_ = (data[0] << 8) | data[1];
    // ����Ŀ�Ķ˿�
    destination_port_ = (data[2] << 8) | data[3];
    // ���� UDP ����
    total_length_ = (data[4] << 8) | data[5];
    // ���� UDP У��ͣ�ʹ����ȷ�� 16 λ������ͣ�
    checksum_ = this->calculate_udp_checksum(data, length, src_ip_, dst_ip_);

    // ������Ч����ָ��ͳ���
    payload_ptr_ = data + UDP_LEN;
    payload_len_ = length - UDP_LEN;
}

std::string UdpParser::summary() const noexcept {
    std::ostringstream oss;
    auto ip_to_str = [](const IPv4Address& ip) {
        std::ostringstream ip_oss;
        ip_oss << static_cast<int>(ip.bytes[0]) << "."
            << static_cast<int>(ip.bytes[1]) << "."
            << static_cast<int>(ip.bytes[2]) << "."
            << static_cast<int>(ip.bytes[3]);
        return ip_oss.str();
    };

    oss << "User Datagram Protocol, Src Port: " << source_port_ << ", Dst Port: " << destination_port_ << std::endl;
    oss << "    Source Port: " << source_port_ << std::endl;
    oss << "    Destination Port: " << destination_port_ << std::endl;
    oss << "    Length: " << total_length_ << std::endl;
    oss << "    Checksum: 0x" << std::hex << std::setfill('0') << std::setw(4) << checksum_ << " [unverified]" << std::endl;
    oss << "    [Checksum Status: Unverified]" << std::endl;
    oss << "    [Stream index: 0]" << std::endl;
    oss << "    [Stream Packet Number: 1]" << std::endl;
    oss << "    [Timestamps]" << std::endl;
    oss << "    UDP payload (" << payload_len_ << " bytes)" << std::endl;

    return oss.str();
}

uint16_t UdpParser::source_port() const {
    return source_port_;
}

uint16_t UdpParser::destination_port() const {
    return destination_port_;
}

uint16_t UdpParser::total_length() const {
    return total_length_;
}

uint16_t UdpParser::checksum() const {
    return checksum_;
}

bool UdpParser::verify_checksum() const{
    uint16_t calculated_checksum = this->calculate_udp_checksum(raw_data(), data_length(), src_ip_, dst_ip_);
    return calculated_checksum == checksum_;
}