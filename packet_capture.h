#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include <pcap.h>
#include <iostream>

#define SNAP_LEN 65535 // 每个数据包的最大长度
#define PROMISC 1 // 是否启用混杂模式（1：是，0：否）
#define TIMEOUT_MS 1000 // 超时时间（单位：毫秒）

// 只处理 UDP 数据包的回调函数
void udp_packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);

// 启动 UDP 数据包捕获
void start_udp_capture(const char *device);

#endif // PACKET_CAPTURE_H