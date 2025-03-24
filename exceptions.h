#pragma once

#include <stdexcept>
#include <string>

// 协议解析异常基类
class ProtocolParseError : public std::runtime_error {
public:
    explicit ProtocolParseError(const std::string& msg)
        : std::runtime_error("[Protocol Error] " + msg) {}
};

// 数据长度异常
class DataLengthError : public ProtocolParseError {
public:
    explicit DataLengthError(size_t expected, size_t actual)
        : ProtocolParseError(
            "Insufficient data length. Expected: " +
            std::to_string(expected) +
            ", Actual: " +
            std::to_string(actual)) {}
};