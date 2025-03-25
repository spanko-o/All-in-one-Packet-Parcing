#include "packet_capture.h"

int main() {
    const char *device = "ens33"; // 网卡
    start_udp_capture(device);
    return 0;
}