#include "ethernet_parser.h"
#include <stdexcept>
#include <iomanip>
#include <sstream>

constexpr size_t ETHERNET_HEADER_LEN = 14;

EthernetParser::EthernetParser(const uint8_t* data, size_t length)
    : ProtocolLayer(data, length){
    parse();  // 传递参数给parse
}

void EthernetParser::parse() {
    // 参数校验
    if (data_length_ < ETHERNET_HEADER_LEN) {
        throw std::runtime_error("Ethernet header too short");
    }

    // 解析MAC地址
    std::copy(raw_data_, raw_data_ + 6, dst_mac_.bytes);
    std::copy(raw_data_ + 6, raw_data_ + 12, src_mac_.bytes);

    // 解析以太类型
    ether_type_ = (raw_data_[12] << 8) | raw_data_[13];  // 手动实现ntohs

    // 设置payload
    payload_ptr_ = raw_data_ + ETHERNET_HEADER_LEN;
    payload_len_ = data_length_ - ETHERNET_HEADER_LEN;

    if (ether_type_ != 0x0800 && ether_type_ != 0x86DD && ether_type_ != 0x8100) {
        throw std::runtime_error("Unsupported EtherType");
    }
}

std::string EthernetParser::summary() const noexcept {
    auto mac_to_str = [](const MacAddress& mac) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (size_t i = 0; i < 6; ++i) {
            if (i != 0) oss << ":";
            oss << std::setw(2) << static_cast<int>(mac.bytes[i]);
        }
        return oss.str();
    };

    std::string type_str;
    switch (ether_type_) {
    case 0x0800: type_str = "IPv4"; break;
    case 0x86DD: type_str = "IPv6"; break;
    default:     type_str = "0x" + std::to_string(ether_type_);
    }

    return "Ethernet [Dst: " + mac_to_str(dst_mac_) +
        ", Src: " + mac_to_str(src_mac_) +
        ", Type: " + type_str + "]";
}