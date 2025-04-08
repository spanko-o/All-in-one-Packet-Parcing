#include "process_packet.h"

void process_packet(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {

    if (!header || !packet || header->caplen == 0) {
        std::cerr << "[ERROR] Invalid packet header or data" << std::endl;
        return;
    }

    std::cout << "\n=== Processing packet (len: " << header->len
        << ", captured: " << header->caplen << ") ===" << std::endl;

    try {
        //创建Packet容器
        Packet pkt(header->ts);

        //解析以太网层
        auto eth_parser = std::make_unique<EthernetParser>(packet, header->caplen);
        pkt.add_layer(std::move(eth_parser));

        //获取以太网层并校验
        const auto* eth_layer = pkt.find_layer<EthernetParser>();
        if (!eth_layer) {
            throw std::runtime_error("Ethernet layer not found");
        }

        std::cout << "[DEBUG] " << eth_layer->summary() << std::endl;

        //解析IPv4层（仅处理IPv4）
        if (eth_layer->ether_type() == 0x0800) {
            auto ipv4_parser = std::make_unique<IPv4Parser>(
                eth_layer->payload(),
                eth_layer->payload_length()
            );
            pkt.add_layer(std::move(ipv4_parser));

            const auto* ipv4_layer = pkt.find_layer<IPv4Parser>();
            if (!ipv4_layer) {
                throw std::runtime_error("IPv4 layer not found");
            }

            std::cout << "[DEBUG] " << ipv4_layer->summary() << std::endl;

            //解析UDP层
            if (ipv4_layer->protocol() == 17) { // UDP
                auto udp_parser = std::make_unique<UdpParser>(
                    ipv4_layer->payload(),
                    ipv4_layer->payload_length(),
                    ipv4_layer->source_ip(),
                    ipv4_layer->destination_ip()
                );
                pkt.add_layer(std::move(udp_parser));

                const auto* udp_layer = pkt.find_layer<UdpParser>();
                if (!udp_layer) {
                    throw std::runtime_error("UDP layer not found");
                }

                std::cout << "[DEBUG] " << udp_layer->summary() << std::endl;

                //解析DNS（仅处理端口53）
                if (udp_layer->source_port() == 53 || udp_layer->destination_port() == 53) {
                    auto dns_parser = std::make_unique<DNSParser>(
                        udp_layer->payload(),
                        udp_layer->payload_length()
                    );
                    pkt.add_layer(std::move(dns_parser));

                    const auto* dns_layer = pkt.find_layer<DNSParser>();
                    if (dns_layer) {
                        std::cout << "[DNS] Query: " << dns_layer->summary() << std::endl;
                    }
                }
            }
        }

        // 输出最终结果
        //std::cout << pkt.to_string() << std::endl;

    }
    catch (const std::exception& e) {
        std::cerr << "[EXCEPTION] " << typeid(e).name() << ": " << e.what() << std::endl;
    }
}