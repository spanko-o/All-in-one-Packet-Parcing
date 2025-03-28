#include <iostream>
#include <cstdio>
#include <vector>
// 假设 dns_parser.h 包含了 DnsPacket、DnsQuery 等类的定义
#include "dns_parser.h"

// 模拟发送数据到 DNS 服务器的函数
void send_to_dns_server(const std::vector<uint8_t>& raw_data) {
    // 这里可以实现实际的网络发送逻辑
    std::cout << "Sending " << raw_data.size() << " bytes to DNS server." << std::endl;
}

int main() {
    // 构造查询数据包
    DnsPacket packet;
    packet.header.set_id(0x1234);
    packet.header.set_rd(true);

    DnsQuery query;
    query.set_name("www.examasdadple.com");
    query.set_type(QType::A);
    packet.queries.push_back(query);

    // 序列化发送
    auto raw_data = packet.serialize();
    send_to_dns_server(raw_data);

    // 模拟接收数据
    
    
    std::vector<uint8_t> received_data = {
    0x12, 0x34,  // Transaction ID: 0x1234 (与你的代码匹配)
    0x81, 0x80,  // Flags: 标准查询响应, 递归查询支持
    0x00, 0x01,  // Questions: 1
    0x00, 0x01,  // Answer RRs: 1
    0x00, 0x00,  // Authority RRs: 0
    0x00, 0x00,  // Additional RRs: 0

    // 查询部分
    0x03, 'w', 'w', 'w',  // "www"
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // "example"
    0x03, 'c', 'o', 'm', 0x00,  // "com" + 终止符
    0x00, 0x01,  // Type: A (IPv4 地址)
    0x00, 0x01,  // Class: IN (互联网)

    // 回答部分
    0xc0, 0x0c,  // Name: 指向查询部分的 www.example.com
    0x00, 0x01,  // Type: A (IPv4 地址)
    0x00, 0x01,  // Class: IN (互联网)
    0x00, 0x00, 0x00, 0x3c,  // TTL: 60 秒
    0x00, 0x04,  // Data length: 4 bytes (IPv4 地址)
    0x93, 0xE0, 0x01, 0x01  // Address: 147.224.1.1 (模拟的 IP)
    };

    // 伪造接收到的数据长度
    size_t received_len = received_data.size();



    // 解析响应
    DnsPacket response;
    if (!received_data.empty() && received_len > 0) {
        response.deserialize(received_data.data(), received_len);
    }
    else {
        // 处理错误：未接收到数据
    }

   

    // 打印结果
    for (const auto& answer : response.answers) {
        if (answer.get_type() == RRType::A) {
            auto& addr = std::get<std::array<uint8_t, 4>>(answer.get_data().data);
            printf("IP: %d.%d.%d.%d\n", addr[0], addr[1], addr[2], addr[3]);
        }
    }

    return 0;
}