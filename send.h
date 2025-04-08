#pragma once

#include <iostream>
#include <vector>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pcap.h>
#include <net/if.h>
#include <linux/if_packet.h>  // 新增头文件
#include <linux/if_ether.h>   // 新增头文件
#include "process_packet.h"

uint16_t calculate_checksum_new(const uint8_t* data, size_t length);

std::vector<uint8_t> construct_dns_request(const std::string& domain_name, const std::string& dst_ip);

void send_and_capture_dns(const std::string& domain_name, const std::string& dst_ip);