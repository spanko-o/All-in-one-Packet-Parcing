#include "dns_parser.h"
#include <iostream>
#include <vector>
#include <iomanip>
#include <sstream>

// 辅助函数：将二进制数据转换为十六进制字符串
std::string hexdump(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        if (i % 16 == 0 && i > 0) oss << "\n";
        else if (i > 0) oss << " ";
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

int main() {
    // 模拟一个简单的 DNS 查询数据包（仅用于测试）
    // 这里的例子是一个查询 "www.example.com" 的 DNS 请求
    std::vector<uint8_t> dns_packet = {
        0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // DNS 头部
        0x03, 'w', 'w', 'w', // "www"
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // "example"
        0x03, 'c', 'o', 'm', // "com"
        0x00, // 结束符
        0x00, 0x01, // 查询类型 A
        0x00, 0x01  // 查询类 IN
    };

    std::cout << "=== DNS 数据包信息 ===\n";
    std::cout << "数据包大小: " << dns_packet.size() << " 字节\n";
    std::cout << "原始数据 (十六进制):\n" << hexdump(dns_packet.data(), dns_packet.size()) << "\n";
    std::cout << "========================\n\n";

    try {
        std::cout << "开始解析 DNS 数据包...\n";
        DNSParser parser(dns_packet.data(), dns_packet.size());
        
        std::cout << "\n=== 解析结果 ===\n";
        std::cout << "协议类型: " << static_cast<int>(parser.type()) << " (DNS)\n";
        std::cout << "摘要信息: " << parser.summary() << "\n";
        std::cout << "查询域名: " << parser.get_domain_name() << "\n";
        
        // 显示 payload 信息
        std::cout << "Payload 大小: " << parser.payload_length() << " 字节\n";
        if (parser.payload_length() > 0) {
            std::cout << "Payload 数据 (十六进制):\n" 
                      << hexdump(parser.payload(), parser.payload_length()) << "\n";
        }
        
        std::cout << "=================\n";
    } catch (const std::exception& e) {
        std::cerr << "解析失败: " << e.what() << "\n";
        std::cerr << "请检查数据包格式是否正确，并确保 DNS_Parser 实现正确处理了所有边界情况。\n";
    }

    return 0;
} 