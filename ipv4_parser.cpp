#include "ipv4_parser.h"
#include <stdexcept>
#include <iomanip>
#include <sstream>

// IPv4头部最小长度（无选项时）
constexpr size_t IPV4_MIN_HEADER_LEN = 20;

IPv4Parser::IPv4Parser(const uint8_t* data, size_t length)
    : ProtocolLayer(data, length){
    parse();
}

void IPv4Parser::parse() {
    const uint8_t* data = raw_data_;
    size_t length = data_length_;
    // 基本长度检查
    if (length < IPV4_MIN_HEADER_LEN) {
        throw std::runtime_error("IPv4 header too short");
    }

    // 解析版本和头部长度（前4位是版本，后4位是IHL）
    uint8_t version_ihl = data[0];
    uint8_t ihl = version_ihl & 0x0F;  // 头部长度（32位字为单位）
    size_t header_bytes = ihl * 4;     // 转换为字节数

    // 验证头部长度
    if (header_bytes < IPV4_MIN_HEADER_LEN || header_bytes > length) {
        throw std::runtime_error("Invalid IPv4 header length");
    }

    // 解析关键字段
    total_length_ = (data[2] << 8) | data[3];  // 总长度（网络字节序）
    ttl_ = data[8];
    protocol_ = data[9];

    // 解析IP地址
    std::copy(data + 12, data + 16, src_ip_.bytes);
    std::copy(data + 16, data + 20, dst_ip_.bytes);

    // 设置payload
    payload_ptr_ = data + header_bytes;
    payload_len_ = total_length_ - header_bytes;

    // 长度二次验证
    if (payload_len_ > (length - header_bytes)) {
        payload_len_ = length - header_bytes;  // 适配实际捕获长度
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

    // 解析版本和头部长度（前4位是版本，后4位是IHL）
    uint8_t version_ihl = raw_data_[0];
    uint8_t ihl = version_ihl & 0x0F;  // 头部长度（32位字为单位）
    size_t header_bytes = ihl * 4;     // 转换为字节数

    // 解析标志位（假设原始数据中存在标志位相关数据）
    uint16_t flags_and_fragment_offset = (raw_data_[6] << 8) | raw_data_[7];
    uint8_t flags = flags_and_fragment_offset >> 13;  // 提取标志位
    uint16_t fragment_offset = flags_and_fragment_offset & 0x1FFF;  // 提取片偏移

    std::string protocol_str;
    switch (protocol_) {
    case 6:  protocol_str = "TCP"; break;
    case 17: protocol_str = "UDP"; break;
    case 1:  protocol_str = "ICMP"; break;
    default: protocol_str = "0x" + std::to_string(protocol_);
    }

    return "IPv4 [Version: " + std::to_string(version_ihl >> 4) +
        ", Header Length: " + std::to_string(header_bytes) + " bytes" +
        ", Src: " + ip_to_str(src_ip_) +
        ", Dst: " + ip_to_str(dst_ip_) +
        ", Proto: " + protocol_str +
        ", TTL: " + std::to_string(ttl_) +
        ", Total Length: " + std::to_string(total_length_) +
        ", Flags: " + std::to_string(flags) +
        ", Fragment Offset: " + std::to_string(fragment_offset) + "]";
}