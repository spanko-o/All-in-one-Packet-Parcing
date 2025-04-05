#include <stdexcept>
#include <iomanip>
#include <sstream>
#include <vector>
#include <cstring>
#include "udp_parser.h"

constexpr size_t UDP_LEN = 8;

// 计算 16 位反码求和的辅助函数
uint16_t UdpParser::calculate_udp_checksum(const uint8_t* data, size_t length, const IPv4Address& src_ip, const IPv4Address& dst_ip) const {
    // 构建伪首部
    uint8_t pseudo_header[12];
    memcpy(pseudo_header, src_ip.bytes, 4);
    memcpy(pseudo_header + 4, dst_ip.bytes, 4);
    pseudo_header[8] = 0;
    pseudo_header[9] = 17;  // UDP 协议号
    pseudo_header[10] = (length >> 8) & 0xff;
    pseudo_header[11] = length & 0xff;

    // 合并伪首部、UDP 首部和数据
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

UdpParser::UdpParser(const uint8_t* data, size_t length, const IPv4Address& src_ip, const IPv4Address& dst_ip)
    : ProtocolLayer(data, length), src_ip_(src_ip), dst_ip_(dst_ip), payload_ptr_(nullptr), payload_len_(0) {
    parse();
}

void UdpParser::parse() {
    const uint8_t* data = raw_data_;
    size_t length = data_length_;
    if (length < UDP_LEN) {
        throw std::runtime_error("UDP packet is too short to have a valid header.");
    }
    // 解析源端口
    source_port_ = (data[0] << 8) | data[1];
    // 解析目的端口
    destination_port_ = (data[2] << 8) | data[3];
    // 解析 UDP 长度
    total_length_ = (data[4] << 8) | data[5];
    // 解析 UDP 校验和（使用正确的 16 位反码求和）
    checksum_ = this->calculate_udp_checksum(data, length, src_ip_, dst_ip_);

    // 设置有效负载指针和长度
    payload_ptr_ = data + UDP_LEN;
    payload_len_ = length - UDP_LEN;
}

std::string UdpParser::summary() const noexcept {
    std::ostringstream oss;
    oss << "UDP Packet Summary:" << std::endl;
    oss << "  Source Port: " << source_port_ << std::endl;
    oss << "  Destination Port: " << destination_port_ << std::endl;
    oss << "  Total Length: " << total_length_ << std::endl;
    oss << "  Checksum: 0x" << std::hex << std::setfill('0') << std::setw(4) << checksum_ << std::endl;
    oss << "  Checksum Verification: " << (verify_checksum() ? "Passed" : "Failed") << std::endl;
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