#pragma once
#include "protocol_layer.h"
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>
#include <arpa/inet.h>

class IPLayer : public ProtocolLayer {
public:
    IPLayer(const uint8_t* packet, size_t length) {
        if (length < sizeof(iphdr)) {
            valid_ = false;
            return;
        }
        valid_ = true;
        const iphdr* ip = reinterpret_cast<const iphdr*>(packet);

        // 解析IP字段
        fields_["Version"] = std::to_string(ip->version);
        fields_["Header Length"] = std::to_string(ip->ihl * 4);
        fields_["Type of Service"] = std::to_string(ip->tos);
        fields_["Total Length"] = std::to_string(ntohs(ip->tot_len));
        fields_["Identification"] = std::to_string(ntohs(ip->id));
        fields_["Flags"] = std::to_string(ip->frag_off >> 13);
        fields_["Fragment Offset"] = std::to_string(ntohs(ip->frag_off) & 0x1FFF);
        fields_["Time to Live"] = std::to_string(ip->ttl);
        fields_["Protocol"] = std::to_string(ip->protocol);
        fields_["Header Checksum"] = std::to_string(ntohs(ip->check));
        fields_["Source IP"] = formatIP(ip->saddr);
        fields_["Dest IP"] = formatIP(ip->daddr);

        size_t header_length = ip->ihl * 4;
        if (length < header_length) {
            valid_ = false;
            return;
        }
        // 确定下一层协议
        if (ip->protocol == IPPROTO_ICMP) {
            next_layer_ = std::make_shared<ICMPLayer>(
                packet + header_length,
                length - header_length
            );
        }
        else if (ip->protocol == IPPROTO_IGMP) {
            next_layer_ = std::make_shared<IGMPLayer>(
                packet + header_length,
                length - header_length
            );
        }
    }

    std::string name() const override { return "IP"; }
    std::unordered_map<std::string, std::string> fields() const override { return fields_; }
    std::shared_ptr<ProtocolLayer> nextLayer() const override { return next_layer_; }
    bool isValid() const override { return valid_; }

private:
    bool valid_ = false;

    static std::string formatIP(uint32_t addr) {
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, buf, sizeof(buf));
        return buf;
    }
};