#include "send.h"

// ����MacAddress��
class MacAddress_new {
public:
    MacAddress_new(const std::string& mac) {
        sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4], &bytes[5]);
    }
    const uint8_t* data() const { return bytes; }
private:
    uint8_t bytes[6];
};

// ����IPv4Address��
class IPv4Address_new {
public:
    IPv4Address_new(const std::string& ip) {
        inet_pton(AF_INET, ip.c_str(), &addr);
    }
    const uint8_t* data() const { return reinterpret_cast<const uint8_t*>(&addr); }
private:
    struct in_addr addr;
};

// ����У���
uint16_t calculate_checksum_new(const uint8_t* data, size_t length) {
    uint32_t sum = 0;
    for (size_t i = 0; i < length; i += 2) {
        uint16_t word = (data[i] << 8) + (i + 1 < length ? data[i + 1] : 0);
        sum += word;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~sum;
}

// ����������ָ�����͵�DNS����
std::vector<uint8_t> construct_dns_request(const std::string& domain_name, const std::string& dst_ip) {
    std::cout << "Constructing DNS request for domain: " << domain_name << std::endl;
    // ��̫����
    MacAddress_new src_mac("00:0c:29:bd:f2:73");
    MacAddress_new dst_mac("00:50:56:fc:61:8e");
    uint16_t ether_type = 0x0800;

    // IP��
    const char* src_ip = "192.168.202.133"; // ����IP��ַ
    const char* target_dst_ip = dst_ip.c_str(); // Ŀ��DNS������IP��ַ
    uint8_t ttl = 64;
    uint8_t protocol = 17; // UDP

    // UDP��
    uint16_t src_port = 12345; // ���Դ�˿�
    uint16_t dst_port = 53; // DNS�˿�

    // DNS��
    uint16_t transaction_id = 0x1234;
    uint16_t flags = 0x0100; // ��׼��ѯ
    uint16_t questions = 1;
    uint16_t query_type = 1; // A ��¼

    // �������ݰ�
    std::vector<uint8_t> packet;

    // �����̫��ͷ
    packet.insert(packet.end(), dst_mac.data(), dst_mac.data() + 6);
    packet.insert(packet.end(), src_mac.data(), src_mac.data() + 6);
    packet.push_back(ether_type >> 8);
    packet.push_back(ether_type & 0xFF);
    std::cout << "Ethernet header added." << std::endl;

    // ���IPͷ
    uint8_t ip_header[20];
    ip_header[0] = 0x45; // �汾��ͷ����
    ip_header[1] = 0; // ��������
    uint16_t total_length = htons(20 + 8 + 12 + domain_name.size() + 2 + 4); // IPͷ + UDPͷ + DNSͷ + ���� + ��ֹ�� + ���ͺ���
    memcpy(&ip_header[2], &total_length, 2);
    ip_header[4] = ip_header[5] = 0; // ��ʶ
    ip_header[6] = ip_header[7] = 0; // ��־��Ƭƫ��
    ip_header[8] = ttl;
    ip_header[9] = protocol;
    ip_header[10] = ip_header[11] = 0; // ͷУ���
    IPv4Address_new src_ip_obj(src_ip);
    IPv4Address_new dst_ip_obj(target_dst_ip);
    memcpy(&ip_header[12], src_ip_obj.data(), 4);
    memcpy(&ip_header[16], dst_ip_obj.data(), 4);
    uint16_t ip_checksum = calculate_checksum_new(ip_header, 20);
    memcpy(&ip_header[10], &ip_checksum, 2);
    packet.insert(packet.end(), ip_header, ip_header + 20);
    std::cout << "IP header added." << std::endl;

    // ���UDPͷ
    uint8_t udp_header[8];
    uint16_t udp_length = htons(8 + 12 + domain_name.size() + 2 + 4); // UDPͷ + DNSͷ + ���� + ��ֹ�� + ���ͺ���
    uint16_t src_port_net = htons(src_port); // ת��Ϊ�����ֽ���
    uint16_t dst_port_net = htons(dst_port); // ת��Ϊ�����ֽ���
    memcpy(&udp_header[0], &src_port_net, 2);
    memcpy(&udp_header[2], &dst_port_net, 2);
    memcpy(&udp_header[4], &udp_length, 2);
    udp_header[6] = 0;
    udp_header[7] = 0; // У�����Ϊ0
    packet.insert(packet.end(), udp_header, udp_header + 8);
    std::cout << "UDP header added." << std::endl;

    // ���DNSͷ
    packet.push_back(transaction_id >> 8);
    packet.push_back(transaction_id & 0xFF);
    packet.push_back(flags >> 8);
    packet.push_back(flags & 0xFF);
    packet.push_back(questions >> 8);
    packet.push_back(questions & 0xFF);
    packet.push_back(0); // Answer RRs
    packet.push_back(0);
    packet.push_back(0); // Authority RRs
    packet.push_back(0);
    packet.push_back(0); // Additional RRs
    packet.push_back(0);
    std::cout << "DNS header added." << std::endl;

    // ���DNS���ⲿ��
    // ������ת��ΪDNS��ʽ
    std::string temp_domain = domain_name;
    size_t pos = 0;
    while ((pos = temp_domain.find('.')) != std::string::npos) {
        packet.push_back(pos);
        packet.insert(packet.end(), temp_domain.begin(), temp_domain.begin() + pos);
        temp_domain.erase(0, pos + 1);
    }
    packet.push_back(temp_domain.size());
    packet.insert(packet.end(), temp_domain.begin(), temp_domain.end());
    packet.push_back(0); // ��ֹ��
    std::cout << "DNS question part added." << std::endl;

    // ���ͺ���
    packet.push_back(0);
    packet.push_back(query_type);
    packet.push_back(0);
    packet.push_back(1); // IN��
    std::cout << "DNS type and class added." << std::endl;

    std::cout << "DNS request packet constructed." << std::endl;
    return packet;
}

// ����DNS���󲢲�����Ӧ
void send_and_capture_dns(const std::string& domain_name, const std::string& dst_ip) {
    std::vector<uint8_t> packet = construct_dns_request(domain_name, dst_ip);

    // ����ԭʼ�׽���
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1) {
        std::cerr << "Error creating socket: " << strerror(errno) << std::endl;
        return;
    }
    std::cout << "Socket created successfully." << std::endl;

    // �������ݰ�
    struct sockaddr_ll socket_address;
    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_ifindex = if_nametoindex("ens33");
    if (socket_address.sll_ifindex == 0) {
        std::cerr << "Error getting interface index for ens33: " << strerror(errno) << std::endl;
        close(sockfd);
        return;
    }
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, packet.data(), ETH_ALEN);

    ssize_t sent = sendto(sockfd, packet.data(), packet.size(), 0, (struct sockaddr*)&socket_address, sizeof(socket_address));
    if (sent == -1) {
        std::cerr << "Error sending packet: " << strerror(errno) << std::endl;
        close(sockfd);
        return;
    }
    std::cout << "DNS request packet sent successfully." << std::endl;

    // ��PCAP�ļ����ڱ�����Ӧ
    pcap_t* pcap;
    pcap_dumper_t* dumper;
    char errbuf[PCAP_ERRBUF_SIZE];
    std::string filename = "dns_response.pcap";
    pcap = pcap_open_dead(DLT_EN10MB, 65535);
    dumper = pcap_dump_open(pcap, filename.c_str());
    if (dumper == nullptr) {
        std::cerr << "Error opening pcap file: " << pcap_geterr(pcap) << std::endl;
        close(sockfd);
        return;
    }
    std::cout << "PCAP file opened successfully for writing responses." << std::endl;

    // ������Ӧ��
    uint8_t buffer[65535];
    struct pcap_pkthdr pcap_header;
    std::cout << "Waiting for DNS response..." << std::endl;
    while (true) {
        ssize_t recv_len = recv(sockfd, buffer, sizeof(buffer), 0);
        if (recv_len > 0) {
            pcap_header.ts.tv_sec = 0;
            pcap_header.ts.tv_usec = 0;
            pcap_header.caplen = recv_len;
            pcap_header.len = recv_len;
            pcap_dump((u_char*)dumper, &pcap_header, buffer);
            std::cout << "DNS response captured and saved to pcap file." << std::endl;
            break;
        }
    }

    // �ر���Դ
    pcap_dump_close(dumper);
    pcap_close(pcap);
    close(sockfd);
    std::cout << "Resources closed." << std::endl;

    pcap_t* handle = pcap_open_offline(filename.c_str(), errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening pcap file: " << errbuf << std::endl;
        return;
    }

    pcap_loop(handle, 0, process_packet, nullptr);
    pcap_close(handle);
}