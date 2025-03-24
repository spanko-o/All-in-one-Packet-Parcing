#pragma once

#include <stdexcept>
#include <string>

// Э������쳣����
class ProtocolParseError : public std::runtime_error {
public:
    explicit ProtocolParseError(const std::string& msg)
        : std::runtime_error("[Protocol Error] " + msg) {}
};

// ���ݳ����쳣
class DataLengthError : public ProtocolParseError {
public:
    explicit DataLengthError(size_t expected, size_t actual)
        : ProtocolParseError(
            "Insufficient data length. Expected: " +
            std::to_string(expected) +
            ", Actual: " +
            std::to_string(actual)) {}
};