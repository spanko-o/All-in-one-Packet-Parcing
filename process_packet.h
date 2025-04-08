#pragma once

#include <pcap.h>
#include <iostream>
#include <typeinfo>
#include "packet_capture.h"
#include "packet.h"
#include "ethernet_parser.h"
#include "ipv4_parser.h"
#include "udp_parser.h"
#include "dns_parser.h"

void process_packet(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);