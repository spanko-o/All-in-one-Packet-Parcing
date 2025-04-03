#pragma once

#include "protocol_layer.h"
#include <string>
#include <vector>

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

    std::string domain_name_;
};