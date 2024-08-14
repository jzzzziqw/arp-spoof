#include <cstdio>   // 표준 입출력 사용을 위한 헤더 파일
#include <pcap.h>   // pcap 라이브러리 사용을 위한 헤더 파일
#include "ethhdr.h" // Ethernet 헤더 구조체를 정의한 커스텀 헤더 파일
#include "arphdr.h" // ARP 헤더 구조체를 정의한 커스텀 헤더 파일
#include <string>   // 문자열 처리를 위한 헤더 파일
#include <net/if.h> // 네트워크 인터페이스 관련 구조체를 위한 헤더 파일
#include <sys/ioctl.h> // 입출력 제어를 위한 헤더 파일
#include <arpa/inet.h> // IP 주소 변환을 위한 헤더 파일
#include <unistd.h> // 시스템 호출을 위한 헤더 파일
#include <vector> // 벡터 자료구조 사용을 위한 헤더 파일

// 구조체의 메모리 정렬을 1바이트로 설정 (패딩 방지)
#pragma pack(push, 1)

// 이더넷 + ARP 패킷 구조체 정의
struct EthArpPacket final {
	EthHdr eth_; // 이더넷 헤더
	ArpHdr arp_; // ARP 헤더
};

#pragma pack(pop) // 메모리 정렬을 기본값으로 복원

// 프로그램 사용법을 출력하는 함수
void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

// fd는 file descriptor
char* get_mac_address(const char* iface) {
    int fd;
    struct ifreq ifr;
    char* mac_addr = (char*)malloc(18);  // 반환할 MAC 주소를 저장할 동적 메모리 할당
    if (mac_addr == NULL) {
        perror("메모리 할당 실패");
        exit(EXIT_FAILURE);
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket 생성 실패");
        free(mac_addr);  // 메모리 해제
        exit(EXIT_FAILURE);
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl 요청 실패");
        close(fd);
        free(mac_addr);  // 메모리 해제
        exit(EXIT_FAILURE);
    }

    close(fd);

    // MAC 주소를 문자열로 변환
    snprintf(mac_addr, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             (unsigned char)ifr.ifr_hwaddr.sa_data[0],
             (unsigned char)ifr.ifr_hwaddr.sa_data[1],
             (unsigned char)ifr.ifr_hwaddr.sa_data[2],
             (unsigned char)ifr.ifr_hwaddr.sa_data[3],
             (unsigned char)ifr.ifr_hwaddr.sa_data[4],
             (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

    return mac_addr;  // 동적 메모리의 주소 반환
}

char* get_ip_address(const char* iface) {
    int fd;
    struct ifreq ifr;
    char* ip_str = (char*)malloc(INET_ADDRSTRLEN); // IP 주소를 저장할 동적 메모리 할당
    if (ip_str == NULL) {
        perror("메모리 할당 실패");
        exit(EXIT_FAILURE);
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket 생성 실패");
        free(ip_str);  // 메모리 해제
        exit(EXIT_FAILURE);
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl 요청 실패");
        close(fd);
        free(ip_str);  // 메모리 해제
        exit(EXIT_FAILURE);
    }

    close(fd);

    // IP 주소를 문자열로 변환
    inet_ntop(AF_INET, &(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), ip_str, INET_ADDRSTRLEN);

    return ip_str;  // 동적 메모리의 주소 반환
}

// 메인 함수
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

    // 에러 메시지를 저장할 버퍼
    char errbuf[PCAP_ERRBUF_SIZE];
    // 장치를 열어 라이브 패킷 캡처를 시작
    pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
    if (handle == nullptr) {
        // 장치를 열 수 없으면 에러 메시지를 출력하고 종료
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    // ARP 패킷 구조체 생성
    EthArpPacket packet;

    std::string my_mac_str = get_mac_address(dev);
    std::string my_ip_str = get_ip_address(dev);

    Mac my_mac(my_mac_str.c_str());
    Ip my_ip(my_ip_str.c_str());

    int res;

    // 패킷을 네트워크로 전송
    for (size_t i = 0; i < sender_ips.size(); ++i) {
        EthArpPacket packet;
        packet = EthArpPacket{
            .eth_ = EthHdr{ Mac("ff:ff:ff:ff:ff:ff"), my_mac, htons(EthHdr::Arp) },
            .arp_ = ArpHdr{
                htons(ArpHdr::ETHER),
                htons(EthHdr::Ip4),
                Mac::SIZE,
                Ip::SIZE,
                htons(ArpHdr::Request),
                my_mac,
                htonl(my_ip),
                Mac("00:00:00:00:00:00"),
                htonl(sender_ips[i])
            }
        };

        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "Error sending ARP request: %d (%s)\n", res, pcap_geterr(handle));
            pcap_close(handle);
            return -1;
        }

        while (true) {
            struct pcap_pkthdr* header;
            const u_char* recv_packet;
            res = pcap_next_ex(handle, &header, &recv_packet);
            if (res == 0) continue;
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                printf("Error capturing packet: %s\n", pcap_geterr(handle));
                break;
            }

            EthArpPacket* recv_etharp = (EthArpPacket*)recv_packet;
            if (recv_etharp->eth_.type_ == htons(EthHdr::Arp) && recv_etharp->arp_.op_ == htons(ArpHdr::Reply)) {
                if (recv_etharp->arp_.sip() == sender_ips[i]) {
                    printf("Received ARP reply from sender. Sender's MAC: %s\n", std::string(recv_etharp->eth_.smac()).c_str());
                    packet.eth_.dmac_ = recv_etharp->eth_.smac_;
                    packet.arp_.tmac_ = recv_etharp->eth_.smac_;
                    break;
                }
            }
        }

        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.sip_ = htonl(target_ips[i]);
        packet.arp_.tip_ = htonl(sender_ips[i]);

        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "Error sending ARP reply: %d (%s)\n", res, pcap_geterr(handle));
        }
    }

    // 네트워크 장치 핸들 닫기
    pcap_close(handle);
    return 0;
}
