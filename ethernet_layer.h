#pragma once
#include <winsock2.h>  // 确保优先引入
#include <ws2tcpip.h>
#include "protocol_layer.h"
#include "ip_layer.h"
// 其他代码...
#define ETHERTYPE_IP 0x0800
#pragma comment(lib, "ws2_32.lib")

class EthernetLayer : public ProtocolLayer {
public:
    EthernetLayer(const uint8_t* packet, size_t length) {
        if (length < sizeof(ETHERNET_HEADER)) {
            valid_ = false;
            return;
        }
        valid_ = true;
        const ETHERNET_HEADER* eth = reinterpret_cast<const ETHERNET_HEADER*>(packet);
        fields_["Source MAC"] = formatMAC(eth->SrcAddr);
        fields_["Dest MAC"] = formatMAC(eth->DstAddr);
        fields_["EtherType"] = formatHex(ntohs(eth->Type));

        size_t remainingLength = length - sizeof(ETHERNET_HEADER);
        uint16_t etherType = ntohs(eth->Type);
        if (etherType == ETHERTYPE_IP && remainingLength >= sizeof(iphdr)) {
            next_layer_ = std::make_shared<IPLayer>(
                packet + sizeof(ETHERNET_HEADER),
                remainingLength
            );
        }
    }

    std::string name() const override { return "Ethernet"; }
    std::unordered_map<std::string, std::string> fields() const override { return fields_; }
    std::shared_ptr<ProtocolLayer> nextLayer() const override { return next_layer_; }
    bool isValid() const override { return valid_; }

private:
    std::string formatMAC(const unsigned char* mac) {
        char buf[18];
        snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return buf;
    }

    std::string formatHex(uint16_t value) {
        char buf[10];
        snprintf(buf, sizeof(buf), "0x%04X", value);
        return buf;
    }

    std::unordered_map<std::string, std::string> fields_;
    std::shared_ptr<ProtocolLayer> next_layer_;
    bool valid_ = false;
};

typedef struct _ETHERNET_HEADER {
    unsigned char DstAddr[6];
    unsigned char SrcAddr[6];
    unsigned short Type;
} ETHERNET_HEADER, * PETHERNET_HEADER;

#define ETHERTYPE_IP 0x0800    