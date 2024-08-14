#include <cstdio>   // ǥ�� ����� �Լ� ����� ���� ��� ����
#include <pcap.h>   // pcap ���̺귯���� ����ϱ� ���� ��� ����
#include "ethhdr.h" // �̴��� ��� ���Ǹ� ���� Ŀ���� ��� ����
#include "arphdr.h" // ARP ��� ���Ǹ� ���� Ŀ���� ��� ����

// ����ü�� �޸� ������ 1����Ʈ�� ���� (�е� ����)
#pragma pack(push, 1)

// �̴��� + ARP ��Ŷ ����ü ����
struct EthArpPacket final {
	EthHdr eth_; // �̴��� ���
	ArpHdr arp_; // ARP ���
};

#pragma pack(pop) // �޸� ������ �⺻������ ����

// ���α׷� ������ ����ϴ� �Լ�
void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

// ���� �Լ�
int main(int argc, char* argv[]) {
	// ���α׷� ���� ���� �ùٸ��� Ȯ��
	if (argc != 2) {
		usage(); // ���� ���� Ʋ���� ���� ���
		return -1;
	}

	// ��Ʈ��ũ ��ġ(�������̽�) �̸� ����
	char* dev = argv[1];
	// ���� �޽����� ������ ����
	char errbuf[PCAP_ERRBUF_SIZE];
	// ��ġ�� ���� ���̺� ��Ŷ ĸó�� ����
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		// ��ġ�� �� �� ������ ���� �޽����� ����ϰ� ����
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	// ARP ��Ŷ ����ü ����
	EthArpPacket packet;

	// �̴��� ��� �ʵ� ����
	packet.eth_.dmac_ = Mac("00:00:00:00:00:00");  // ������ MAC �ּ�
	packet.eth_.smac_ = Mac("00:00:00:00:00:00");  // ����� MAC �ּ�
	packet.eth_.type_ = htons(EthHdr::Arp);        // �̴��� Ÿ��: ARP

	// ARP ��� �ʵ� ����
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);      // �ϵ���� Ÿ��: �̴���
	packet.arp_.pro_ = htons(EthHdr::Ip4);        // �������� Ÿ��: IPv4
	packet.arp_.hln_ = Mac::SIZE;                 // �ϵ���� �ּ� ����
	packet.arp_.pln_ = Ip::SIZE;                  // �������� �ּ� ����
	packet.arp_.op_ = htons(ArpHdr::Request);     // ARP ���۷��̼� Ÿ��: ��û
	packet.arp_.smac_ = Mac("00:00:00:00:00:00"); // ����� MAC �ּ�
	packet.arp_.sip_ = htonl(Ip("0.0.0.0"));      // ����� IP �ּ�
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // ������ MAC �ּ�
	packet.arp_.tip_ = htonl(Ip("0.0.0.0"));      // ������ IP �ּ�

	// ��Ŷ�� ��Ʈ��ũ�� ����
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		// ���� ���� �� ���� �޽��� ���
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	// ��Ʈ��ũ ��ġ �ڵ� �ݱ�
	pcap_close(handle);
}
