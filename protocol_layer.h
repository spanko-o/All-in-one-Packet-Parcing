#pragma once
#include <memory>
#include <string>
#include <unordered_map>

class ProtocolLayer {
public:
    virtual ~ProtocolLayer() = default;
    virtual std::string name() const = 0;
    virtual std::unordered_map<std::string, std::string> fields() const = 0;
    virtual std::shared_ptr<ProtocolLayer> nextLayer() const = 0;
    virtual bool isValid() const = 0;
};