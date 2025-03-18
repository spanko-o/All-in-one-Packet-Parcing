#include <iostream>
#include "ethernet_layer.h"

void printProtocolStack(const std::shared_ptr<ProtocolLayer>& layer, int depth = 0) {
    if (!layer || !layer->isValid()) return;
    std::cout << std::string(depth * 2, ' ') << "Layer: " << layer->name() << std::endl;
    auto fields = layer->fields();
    for (const auto& [key, value] : fields) {
        std::cout << std::string((depth + 1) * 2, ' ') << key << ": " << value << std::endl;
    }
    if (layer->nextLayer()) {
        std::cout << std::string((depth + 1) * 2, ' ') << "Next layer pointer is valid." << std::endl;
    }
    else {
        std::cout << std::string((depth + 1) * 2, ' ') << "Next layer pointer is null." << std::endl;
    }
    printProtocolStack(layer->nextLayer(), depth + 1);
}

int main() {
    // 初始化 Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed." << std::endl;
        return 1;
    }

    // 模拟一个简单的以太网 + IP 数据包
    uint8_t packet[1024];
    ETHERNET_HEADER* ethHeader = reinterpret_cast<ETHERNET_HEADER*>(packet);
    memset(ethHeader->DstAddr, 0xFF, 6);
    memset(ethHeader->SrcAddr, 0xAA, 6);
    ethHeader->Type = htons(ETHERTYPE_IP);

    iphdr* ipHeader = reinterpret_cast<iphdr*>(packet + sizeof(ETHERNET_HEADER));
    ipHeader->version = 4;
    ipHeader->ihl = 5;
    ipHeader->saddr = inet_addr("192.168.1.1");
    ipHeader->daddr = inet_addr("192.168.1.2");
    ipHeader->protocol = IPPROTO_TCP;

    size_t packetLength = sizeof(ETHERNET_HEADER) + sizeof(iphdr);

    // 从数据链路层开始构建协议栈
    auto ethLayer = std::make_shared<EthernetLayer>(packet, packetLength);

    // 遍历并打印协议栈，检查指针有效性
    printProtocolStack(ethLayer);

    // 清理 Winsock
    WSACleanup();

    return 0;
}