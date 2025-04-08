#include "dns_parser.h"
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <vector>

DNSParser::DNSParser(const uint8_t* data, size_t length)
    : ProtocolLayer(data, length) {
    parse();
}

// 辅助函数：解析域名
std::string DNSParser::parse_domain_name(const uint8_t*& ptr, size_t& remaining_length) {
    std::ostringstream domain_stream;
    while (remaining_length > 0) {
        uint8_t label_length = *ptr;
        if (label_length == 0) {
            ptr++;
            remaining_length--;
            break;
        }
        if ((label_length & 0xC0) == 0xC0) { // 处理指针引用
            uint16_t offset = ((label_length & 0x3F) << 8) | *(ptr + 1);
            const uint8_t* new_ptr = raw_data_ + offset;
            size_t new_remaining_length = data_length_ - offset;
            domain_stream << parse_domain_name(new_ptr, new_remaining_length);
            ptr += 2;
            remaining_length -= 2;
            break;
        }
        if (label_length > remaining_length - 1) {
            throw std::runtime_error("Invalid DNS label length");
        }

        if (domain_stream.str().length() > 0) {
            domain_stream << ".";
        }

        // 临时存储当前标签
        std::string current_label(reinterpret_cast<const char*>(ptr + 1), label_length);
        domain_stream << current_label;

        // 检查当前标签是否为 "ns"，如果是则添加点
        if (current_label == "ns") {
            domain_stream << ".";
        }

        ptr += label_length + 1;
        remaining_length -= label_length + 1;
    }
    return domain_stream.str();
}
// 辅助函数：解析资源记录
ResourceRecord DNSParser::parse_resource_record(const uint8_t*& ptr, size_t& remaining_length) {
    std::ostringstream oss;
    ResourceRecord rr;
    rr.name = parse_domain_name(ptr, remaining_length);
    rr.type = (ptr[0] << 8) | ptr[1];
    rr.rr_class = (ptr[2] << 8) | ptr[3];
    rr.ttl = (ptr[4] << 24) | (ptr[5] << 16) | (ptr[6] << 8) | ptr[7];
    rr.data_length = (ptr[8] << 8) | ptr[9];
    ptr += 10;
    remaining_length -= 10;

    std::ostringstream data_stream;
    if (rr.type == 1) { // A 记录
        data_stream << static_cast<int>(ptr[0]) << "."
            << static_cast<int>(ptr[1]) << "."
            << static_cast<int>(ptr[2]) << "."
            << static_cast<int>(ptr[3]);
        ptr += 4;
        remaining_length -= 4;
    }
    else if (rr.type == 2) { // NS 记录
        data_stream << parse_domain_name(ptr, remaining_length);
    }
    else if (rr.type == 6) { // SOA 记录
        std::string mname = parse_domain_name(ptr, remaining_length);
        std::string rname = parse_domain_name(ptr, remaining_length);
        uint32_t serial = (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
        uint32_t refresh = (ptr[4] << 24) | (ptr[5] << 16) | (ptr[6] << 8) | ptr[7];
        uint32_t retry = (ptr[8] << 24) | (ptr[9] << 16) | (ptr[10] << 8) | ptr[11];
        uint32_t expire = (ptr[12] << 24) | (ptr[13] << 16) | (ptr[14] << 8) | ptr[15];
        uint32_t minimum = (ptr[16] << 24) | (ptr[17] << 16) | (ptr[18] << 8) | ptr[19];
        ptr += 20;
        remaining_length -= 20;

        data_stream << "MNAME: " << mname << ", RNAME: " << rname
            << ", Serial: " << serial
            << ", Refresh: " << refresh
            << ", Retry: " << retry
            << ", Expire: " << expire
            << ", Minimum: " << minimum;
    }
    else {
        oss << "Unknown record type: 0x" << std::hex << rr.type << ", skipping data parsing." << std::endl;
    }
    rr.data = data_stream.str();
    ptr += rr.data_length;
    remaining_length -= rr.data_length;
    return rr;
}

void DNSParser::parse() {
    const uint8_t* ptr = raw_data_;
    size_t remaining_length = data_length_;

    // 解析 DNS 头部
    transaction_id_ = (ptr[0] << 8) | ptr[1];
    flags_ = (ptr[2] << 8) | ptr[3];
    questions_ = (ptr[4] << 8) | ptr[5];
    answer_rrs_ = (ptr[6] << 8) | ptr[7];
    authority_rrs_ = (ptr[8] << 8) | ptr[9];
    additional_rrs_ = (ptr[10] << 8) | ptr[11];

    ptr += 12;
    remaining_length -= 12;

    // 解析查询部分
    for (int i = 0; i < questions_; ++i) {
        domain_name_ = parse_domain_name(ptr, remaining_length);
        query_type_ = (ptr[0] << 8) | ptr[1];
        query_class_ = (ptr[2] << 8) | ptr[3];
        ptr += 4;
        remaining_length -= 4;
    }

    // 解析回答资源记录
    for (int i = 0; i < answer_rrs_; ++i) {
        answer_records_.push_back(parse_resource_record(ptr, remaining_length));
    }

    // 解析权威资源记录
    for (int i = 0; i < authority_rrs_; ++i) {
        authority_records_.push_back(parse_resource_record(ptr, remaining_length));
    }

    // 解析额外资源记录
    for (int i = 0; i < additional_rrs_; ++i) {
        additional_records_.push_back(parse_resource_record(ptr, remaining_length));
    }

    // 设置 payload_ptr_ 和 payload_len_
    payload_ptr_ = ptr;
    payload_len_ = remaining_length;
}

ProtocolType DNSParser::type() const noexcept {
    return ProtocolType::DNS;
}

std::string DNSParser::summary() const noexcept {
    std::ostringstream oss;
    std::string response_type = (flags_ & 0x8000) ? "response" : "query";
    oss << "Domain Name System (" << response_type << ")" << std::endl;
    oss << "    Transaction ID: 0x" << std::hex << std::setfill('0') << std::setw(4) << transaction_id_ << std::endl;
    oss << "    Flags: 0x" << std::hex << std::setfill('0') << std::setw(4) << flags_;
    if (flags_ == 0x0120) {
        oss << " Standard query";
    }
    else if (flags_ == 0x81a0) {
        oss << " Standard query response, No error";
    }
    oss << std::endl;
    oss << "    Questions: " << std::dec << questions_ << std::endl;
    oss << "    Answer RRs: " << std::dec << answer_rrs_ << std::endl;
    oss << "    Authority RRs: " << std::dec << authority_rrs_ << std::endl;
    oss << "    Additional RRs: " << std::dec << additional_rrs_ << std::endl;
    oss << "    Queries" << std::endl;
    oss << "        " << domain_name_ << ": type ";
    switch (query_type_) {
    case 1:
        oss << "A";
        break;
    case 2:
        oss << "NS";
        break;
    case 5:
        oss << "CNAME";
        break;
    case 15:
        oss << "MX";
        break;
    default:
        oss << "0x" << std::hex << query_type_;
        break;
    }
    oss << ", class ";
    if (query_class_ == 1) {
        oss << "IN";
    }
    else {
        oss << "0x" << std::hex << query_class_;
    }
    oss << std::endl;

    // 输出回答资源记录
    if (!answer_records_.empty()) {
        oss << "    Answers" << std::endl;
        for (const auto& rr : answer_records_) {
            oss << "        " << rr.name << ": type ";
            switch (rr.type) {
            case 1:
                oss << "A";
                break;
            case 2:
                oss << "NS";
                break;
            case 5:
                oss << "CNAME";
                break;
            case 15:
                oss << "MX";
                break;
            default:
                oss << "0x" << std::hex << rr.type;
                break;
            }
            oss << ", class ";
            if (rr.rr_class == 1) {
                oss << "IN";
            }
            else {
                oss << "0x" << std::hex << rr.rr_class;
            }
            oss << ", TTL: " << std::dec << rr.ttl << ", Data: " << rr.data << std::endl;
        }
    }

    // 输出权威资源记录
    if (!authority_records_.empty()) {
        oss << "    Authoritative nameservers" << std::endl;
        for (const auto& rr : authority_records_) {
            oss << "        " << rr.name << ": type ";
            switch (rr.type) {
            case 1:
                oss << "A";
                break;
            case 2:
                oss << "NS";
                break;
            case 5:
                oss << "CNAME";
                break;
            case 15:
                oss << "MX";
                break;
            default:
                oss << "0x" << std::hex << rr.type;
                break;
            }
            oss << ", class ";
            if (rr.rr_class == 1) {
                oss << "IN";
            }
            else {
                oss << "0x" << std::hex << rr.rr_class;
            }
            oss << ", TTL: " << std::dec << rr.ttl << ", Data: " << rr.data << std::endl;
        }
    }

    // 输出额外资源记录
    if (!additional_records_.empty()) {
        oss << "    Additional records" << std::endl;
        for (const auto& rr : additional_records_) {
            oss << "        " << rr.name << ": type ";
            switch (rr.type) {
            case 1:
                oss << "A";
                break;
            case 2:
                oss << "NS";
                break;
            case 5:
                oss << "CNAME";
                break;
            case 15:
                oss << "MX";
                break;
            default:
                oss << "0x" << std::hex << rr.type;
                break;
            }
            oss << ", class ";
            if (rr.rr_class == 1) {
                oss << "IN";
            }
            else {
                oss << "0x" << std::hex << rr.rr_class;
            }
            oss << ", TTL: " << std::dec << rr.ttl << ", Data: " << rr.data << std::endl;
        }
    }

    return oss.str();
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