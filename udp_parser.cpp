#include <stdexcept>
#include <iomanip>
#include <sstream>
#include <vector>
#include "udp_parser.h"

constexpr size_t UDP_LEN = 8;

// CRC32 ����ʽ
const uint32_t CRC32_POLYNOMIAL = 0xEDB88320;
// Ԥ����� CRC32 ��
std::vector<uint32_t> crc32_table;

// ��ʼ�� CRC32 ��
void init_crc32_table() {
    crc32_table.resize(256);
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        for (int j = 0; j < 8; ++j) {
            if (crc & 1) {
                crc = (crc >> 1) ^ CRC32_POLYNOMIAL;
            }
            else {
                crc >>= 1;
            }
        }
        crc32_table[i] = crc;
    }
}

// ���� CRC32 У���
uint32_t calculate_crc32(const uint8_t* data, size_t length) {
    if (crc32_table.empty()) {
        init_crc32_table();
    }
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; ++i) {
        uint8_t index = (crc ^ data[i]) & 0xFF;
        crc = (crc >> 8) ^ crc32_table[index];
    }
    return crc ^ 0xFFFFFFFF;
}

UdpParser::UdpParser(const uint8_t* data, size_t length, const IPv4Address& src_ip, const IPv4Address& dst_ip)
    : ProtocolLayer(data, length), src_ip_(src_ip), dst_ip_(dst_ip), payload_ptr_(nullptr), payload_len_(0) {
    parse(data, length);
}

void UdpParser::parse(const uint8_t* data, size_t length) {
    if (length < UDP_LEN) {
        throw std::runtime_error("UDP packet is too short to have a valid header.");
    }
    // ����Դ�˿�
    source_port_ = (data[0] << 8) | data[1];
    // ����Ŀ�Ķ˿�
    destination_port_ = (data[2] << 8) | data[3];
    // ���� UDP ����
    total_length_ = (data[4] << 8) | data[5];
    // ���� UDP У��ͣ���������� CRC32 У��ͣ�
    checksum_ = static_cast<uint16_t>(calculate_crc32(data, length));

    // ������Ч����ָ��ͳ���
    payload_ptr_ = data + UDP_LEN;
    payload_len_ = length - UDP_LEN;
}

std::string UdpParser::summary() const noexcept {
    std::ostringstream oss;
    oss << "UDP Packet Summary:" << std::endl;
    oss << "  Source Port: " << source_port_ << std::endl;
    oss << "  Destination Port: " << destination_port_ << std::endl;
    oss << "  Total Length: " << total_length_ << std::endl;
    oss << "  Checksum: 0x" << std::hex << std::setfill('0') << std::setw(8) << checksum_ << std::endl;
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

uint32_t UdpParser::checksum() const {
    return checksum_;
}

bool UdpParser::verify_checksum() const {
    // ����α�ײ�
    uint8_t pseudo_header[12];
    std::memcpy(pseudo_header, src_ip_.bytes, 4);
    std::memcpy(pseudo_header + 4, dst_ip_.bytes, 4);
    pseudo_header[8] = 0;
    pseudo_header[9] = 17;  // UDP Э���
    pseudo_header[10] = (total_length_ >> 8) & 0xff;
    pseudo_header[11] = total_length_ & 0xff;

    // �ϲ�α�ײ���UDP �ײ�������
    std::vector<uint8_t> buffer;
    buffer.insert(buffer.end(), pseudo_header, pseudo_header + 12);
    buffer.insert(buffer.end(), raw_data(), raw_data() + data_length());

    // ���� CRC32 У���
    uint32_t calculated_checksum = calculate_crc32(buffer.data(), buffer.size());

    // ��֤У���
    return calculated_checksum == checksum_;
}