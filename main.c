#include "net_headers.h"

void usage()
{
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct
{
	char *dev_;
} Param;

Param param = {
	.dev_ = NULL};

bool parse(Param *param, int argc, char *argv[])
{
	if (argc != 2)
	{
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char *argv[])
{
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];										// 256
	pcap_t *pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf); // BUFSIZ 8192
	if (pcap == NULL)
	{
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true)
	{
		int offset = 0;
		struct pcap_pkthdr *header;
		const u_char *packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0)
			continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
		{
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		// print_uchar_as_hex((void *)packet, header->caplen);
		printf("\n");

		my_ether_hdr ether_hdr;
		memcpy(&ether_hdr.des_mac, packet + offset, 6); offset+=6;
		memcpy(&ether_hdr.src_mac, packet + offset, 6); offset+=6;
		memcpy(&ether_hdr.ether_type, packet + offset, 2); offset+=2;

		print_ether_macs(ether_hdr);

		if (ntohs(ether_hdr.ether_type) != 0x0800){printf("type is not ip\n"); continue;}

		my_ip_hdr ip_hdr;
		memcpy(&ip_hdr, packet+offset, 1); offset+=1;
		memcpy(&ip_hdr.type_of_service, packet+offset, 1); offset+=1;
		memcpy(&ip_hdr.total_length, packet+offset, 2); offset+=2;
		memcpy(&ip_hdr.id, packet+offset, 2); offset+=2;
		memcpy(&ip_hdr.id+2, packet+offset, 2); offset+=2;
		memcpy(&ip_hdr.time_to_live, packet+offset, 1); offset+=1;
		memcpy(&ip_hdr.protocol, packet+offset, 1); offset+=1;
		memcpy(&ip_hdr.hdr_checksum, packet+offset, 2); offset+=2;
		memcpy(&ip_hdr.src_addr, packet+offset, 4); offset+=4;
		memcpy(&ip_hdr.des_addr, packet+offset, 4); offset+=4;

		print_ip_addrs(ip_hdr);

		if (ip_hdr.protocol!= 0x06){printf("protocol is not tcp\n"); continue;}

		my_tcp_hdr tcp_hdr;
		memcpy(&tcp_hdr.src_port, packet+offset, 2); offset+=2;
		memcpy(&tcp_hdr.des_port, packet+offset, 2); offset+=2;
		memcpy(&tcp_hdr.seq_num, packet+offset, 4); offset+=4;
		memcpy(&tcp_hdr.ack_num, packet+offset, 4); offset+=4;
		memcpy(&tcp_hdr.ack_num+1, packet+offset, 2); offset+=2; // can't write on bit field
		// 주소에 1을 더하면 1byte가 늘어나지 않고 4byte가 늘어남. &tcp_hdr.ack_num가 4byte 자료형의 포인터이기 때문.
		memcpy(&tcp_hdr.window_size, packet+offset, 2); offset+=2;
		memcpy(&tcp_hdr.checksum, packet+offset, 2); offset+=2;
		memcpy(&tcp_hdr.urgent_pointer, packet+offset, 2); offset+=2;

		print_tcp_ports(tcp_hdr);
	}

	pcap_close(pcap);
}
