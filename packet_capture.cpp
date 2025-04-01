#include "packet_capture.h"

// 只处理 UDP 数据包的回调函数
void udp_packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    std::cout << "捕获到 UDP 数据包 - 长度: " << header->len << " 字节"
        << " 时间戳: " << header->ts.tv_sec << std::endl;
}

// 启动 UDP 数据包捕获
void start_udp_capture(const char* device) {
    char errbuf[PCAP_ERRBUF_SIZE]; // 错误信息缓冲区
    pcap_t* handle;

    // 打开网络接口
    handle = pcap_open_live(device, SNAP_LEN, PROMISC, TIMEOUT_MS, errbuf);

    if (handle == nullptr) {
        std::cerr << "无法打开设备 " << device << ": " << errbuf << std::endl;
        return;
    }

    std::cout << "正在监听设备: " << device << " (仅捕获 UDP 数据包)" << std::endl;

    // 只捕获 UDP 数据包的 BPF 过滤规则
    struct bpf_program filter;

    if (pcap_compile(handle, &filter, "udp", 1, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "无法编译 BPF 过滤规则: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return;
    }

    if (pcap_setfilter(handle, &filter) == -1) {
        std::cerr << "无法设置 BPF 过滤规则: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return;
    }

    // 开始捕获 UDP 数据包
    pcap_loop(handle, 0, udp_packet_handler, nullptr); // 0 表示无限循环

    // 关闭会话
    pcap_close(handle);
}