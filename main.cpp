#include <cstdio>   // 표준 입출력 함수 사용을 위한 헤더 파일
#include <pcap.h>   // pcap 라이브러리를 사용하기 위한 헤더 파일
#include "ethhdr.h" // 이더넷 헤더 정의를 위한 커스텀 헤더 파일
#include "arphdr.h" // ARP 헤더 정의를 위한 커스텀 헤더 파일

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

// 메인 함수
int main(int argc, char* argv[]) {
	// 프로그램 인자 수가 올바른지 확인
	if (argc != 2) {
		usage(); // 인자 수가 틀리면 사용법 출력
		return -1;
	}

	// 네트워크 장치(인터페이스) 이름 저장
	char* dev = argv[1];
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

	// 이더넷 헤더 필드 설정
	packet.eth_.dmac_ = Mac("00:00:00:00:00:00");  // 목적지 MAC 주소
	packet.eth_.smac_ = Mac("00:00:00:00:00:00");  // 출발지 MAC 주소
	packet.eth_.type_ = htons(EthHdr::Arp);        // 이더넷 타입: ARP

	// ARP 헤더 필드 설정
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);      // 하드웨어 타입: 이더넷
	packet.arp_.pro_ = htons(EthHdr::Ip4);        // 프로토콜 타입: IPv4
	packet.arp_.hln_ = Mac::SIZE;                 // 하드웨어 주소 길이
	packet.arp_.pln_ = Ip::SIZE;                  // 프로토콜 주소 길이
	packet.arp_.op_ = htons(ArpHdr::Request);     // ARP 오퍼레이션 타입: 요청
	packet.arp_.smac_ = Mac("00:00:00:00:00:00"); // 출발지 MAC 주소
	packet.arp_.sip_ = htonl(Ip("0.0.0.0"));      // 출발지 IP 주소
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // 목적지 MAC 주소
	packet.arp_.tip_ = htonl(Ip("0.0.0.0"));      // 목적지 IP 주소

	// 패킷을 네트워크로 전송
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		// 전송 실패 시 에러 메시지 출력
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	// 네트워크 장치 핸들 닫기
	pcap_close(handle);
}
