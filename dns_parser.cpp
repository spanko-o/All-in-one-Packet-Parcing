#include "dns_parser.h"
#include <stdexcept>
#include <sstream>

DNSParser::DNSParser(const uint8_t* data, size_t length)
    : ProtocolLayer(data, length) {
    parse();
}

void DNSParser::parse() {
    // ���� DNS ���ݰ��Ŀ�ʼ�� DNS ͷ��������ͷ����12�ֽ�
    const uint8_t* ptr = raw_data_ + 12;
    size_t remaining_length = data_length_ - 12;

    // ��������
    std::ostringstream domain_stream;
    while (remaining_length > 0) {
        uint8_t label_length = *ptr;
        if (label_length == 0) {
            break;
        }
        if (label_length > remaining_length - 1) {
            throw std::runtime_error("Invalid DNS label length");
        }
        if (!domain_stream.str().empty()) {
            domain_stream << ".";
        }
        domain_stream.write(reinterpret_cast<const char*>(ptr + 1), label_length);
        ptr += label_length + 1;
        remaining_length -= label_length + 1;
    }

    domain_name_ = domain_stream.str();

    // ���� payload_ptr_ �� payload_len_
    payload_ptr_ = ptr;
    payload_len_ = remaining_length;
}

ProtocolType DNSParser::type() const noexcept {
    return ProtocolType::DNS;
}

std::string DNSParser::summary() const noexcept {
    return "DNS [Domain: " + domain_name_ + "]";
}

const uint8_t* DNSParser::payload() const noexcept {
    return payload_ptr_;
}

size_t DNSParser::payload_length() const noexcept {
    return payload_len_;
}

std::string DNSParser::get_domain_name() const {
    return domain_name_;
}
