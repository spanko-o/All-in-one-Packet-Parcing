#pragma once

#include <pcap.h>
#include <iostream>

#define SNAP_LEN 65535 // ÿ�����ݰ�����󳤶�
#define PROMISC 1 // �Ƿ����û���ģʽ��1���ǣ�0����
#define TIMEOUT_MS 1000 // ��ʱʱ�䣨��λ�����룩

// ֻ���� UDP ���ݰ��Ļص�����
void udp_packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);

// ���� UDP ���ݰ�����
void start_udp_capture(const char* device);