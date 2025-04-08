#include <pcap.h>
#include <iostream>
#include <typeinfo>
#include "send.cpp"

int main() {
    std::string domain_name, dst_ip;
    std::cout << "Please enter the domain name: ";
    std::cin >> domain_name;
    std::cout << "Please enter the DNS server IP address: ";
    std::cin >> dst_ip;

    send_and_capture_dns(domain_name, dst_ip);

    return 0;
}