#pragma once

#include "protocol_layer.h"
#include <string>
#include <vector>
#include <cstdint>

// 定义一个结构体来存储资源记录信息
struct ResourceRecord {
    std::string name;
    uint16_t type;
    uint16_t rr_class;
    uint32_t ttl;
    uint16_t data_length;
    std::string data;
};

class DNSParser : public ProtocolLayer {
public:
    DNSParser(const uint8_t* data, size_t length);

    ProtocolType type() const noexcept override;

    std::string summary() const noexcept override;

    const uint8_t* payload() const noexcept override;

    size_t payload_length() const noexcept override;

    std::string get_domain_name() const;

private:
    void parse();
    // 辅助函数：解析域名
    std::string parse_domain_name(const uint8_t*& ptr, size_t& remaining_length);
    // 辅助函数：解析资源记录
    ResourceRecord parse_resource_record(const uint8_t*& ptr, size_t& remaining_length);

    std::string domain_name_;
    const uint8_t* payload_ptr_;
    size_t payload_len_;
    uint16_t transaction_id_;
    uint16_t flags_;
    uint16_t questions_;
    uint16_t answer_rrs_;
    uint16_t authority_rrs_;
    uint16_t additional_rrs_;
    uint16_t query_type_;
    uint16_t query_class_;
    std::vector<ResourceRecord> answer_records_;
    std::vector<ResourceRecord> authority_records_;
    std::vector<ResourceRecord> additional_records_;
};