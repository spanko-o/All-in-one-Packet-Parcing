#include "dns_parser.h"
#include <iostream>
#include <vector>
#include <iomanip>
#include <sstream>

// ����������������������ת��Ϊʮ�������ַ���
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
    // ģ��һ���򵥵� DNS ��ѯ���ݰ��������ڲ��ԣ�
    // �����������һ����ѯ "www.example.com" �� DNS ����
    std::vector<uint8_t> dns_packet = {
        0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // DNS ͷ��
        0x03, 'w', 'w', 'w', // "www"
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // "example"
        0x03, 'c', 'o', 'm', // "com"
        0x00, // ������
        0x00, 0x01, // ��ѯ���� A
        0x00, 0x01  // ��ѯ�� IN
    };

    std::cout << "=== DNS ���ݰ���Ϣ ===\n";
    std::cout << "���ݰ���С: " << dns_packet.size() << " �ֽ�\n";
    std::cout << "ԭʼ���� (ʮ������):\n" << hexdump(dns_packet.data(), dns_packet.size()) << "\n";
    std::cout << "========================\n\n";

    try {
        std::cout << "��ʼ���� DNS ���ݰ�...\n";
        DNSParser parser(dns_packet.data(), dns_packet.size());
        
        std::cout << "\n=== ������� ===\n";
        std::cout << "Э������: " << static_cast<int>(parser.type()) << " (DNS)\n";
        std::cout << "ժҪ��Ϣ: " << parser.summary() << "\n";
        std::cout << "��ѯ����: " << parser.get_domain_name() << "\n";
        
        // ��ʾ payload ��Ϣ
        std::cout << "Payload ��С: " << parser.payload_length() << " �ֽ�\n";
        if (parser.payload_length() > 0) {
            std::cout << "Payload ���� (ʮ������):\n" 
                      << hexdump(parser.payload(), parser.payload_length()) << "\n";
        }
        
        std::cout << "=================\n";
    } catch (const std::exception& e) {
        std::cerr << "����ʧ��: " << e.what() << "\n";
        std::cerr << "�������ݰ���ʽ�Ƿ���ȷ����ȷ�� DNS_Parser ʵ����ȷ���������б߽������\n";
    }

    return 0;
} 