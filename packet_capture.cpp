#include "packet_capture.h"

// ֻ���� UDP ���ݰ��Ļص�����
void udp_packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    std::cout << "���� UDP ���ݰ� - ����: " << header->len << " �ֽ�"
        << " ʱ���: " << header->ts.tv_sec << std::endl;
}

// ���� UDP ���ݰ�����
void start_udp_capture(const char* device) {
    char errbuf[PCAP_ERRBUF_SIZE]; // ������Ϣ������
    pcap_t* handle;

    // ������ӿ�
    handle = pcap_open_live(device, SNAP_LEN, PROMISC, TIMEOUT_MS, errbuf);

    if (handle == nullptr) {
        std::cerr << "�޷����豸 " << device << ": " << errbuf << std::endl;
        return;
    }

    std::cout << "���ڼ����豸: " << device << " (������ UDP ���ݰ�)" << std::endl;

    // ֻ���� UDP ���ݰ��� BPF ���˹���
    struct bpf_program filter;

    if (pcap_compile(handle, &filter, "udp", 1, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "�޷����� BPF ���˹���: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return;
    }

    if (pcap_setfilter(handle, &filter) == -1) {
        std::cerr << "�޷����� BPF ���˹���: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return;
    }

    // ��ʼ���� UDP ���ݰ�
    pcap_loop(handle, 0, udp_packet_handler, nullptr); // 0 ��ʾ����ѭ��

    // �رջỰ
    pcap_close(handle);
}