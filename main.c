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

		print_uchar_as_hex((void *)packet, header->caplen);
		printf("\n");

		my_ether_hdr ether_hdr;
		memcpy(&ether_hdr.des_mac, packet + 0, 6);
		memcpy(&ether_hdr.src_mac, packet + 6, 6);
		memcpy(&ether_hdr.ether_type, packet + 12, 2);

		print_ether_macs(ether_hdr);

		if (ntohs(ether_hdr.ether_type) != 0x0800){printf("type is not ip\n"); continue;}

		my_ip_hdr ip_hdr;
		memcpy(&ip_hdr, packet+14, 1);
		memcpy(&ip_hdr.type_of_service, packet+15, 1);
		memcpy(&ip_hdr.total_length, packet+16, 2);
		memcpy(&ip_hdr.id, packet+18, 2);
		memcpy(&ip_hdr.id+2, packet+20, 2);
		memcpy(&ip_hdr.time_to_live, packet+22, 1);
		memcpy(&ip_hdr.protocol, packet+23, 1);
		memcpy(&ip_hdr.hdr_checksum, packet+24, 2);
		memcpy(&ip_hdr.src_addr, packet+26, 4);
		memcpy(&ip_hdr.des_addr, packet+30, 4);

		print_ip_addrs(ip_hdr);

		if (ip_hdr.protocol!= 0x06){printf("protocol is not tcp\n"); continue;}

		my_tcp_hdr tcp_hdr;
		memcpy(&tcp_hdr.src_port, packet+34, 2);
		memcpy(&tcp_hdr.des_port, packet+36, 2);
		memcpy(&tcp_hdr.seq_num, packet+38, 4);
		memcpy(&tcp_hdr.ack_num, packet+42, 4);
		memcpy(&tcp_hdr.ack_num+4, packet+46, 2); // can't write on bit field
		memcpy(&tcp_hdr.window_size, packet+48, 2);
		memcpy(&tcp_hdr.checksum, packet+50, 2);
		memcpy(&tcp_hdr.urgent_pointer, packet+52, 2);

		print_tcp_info(tcp_hdr);
	
	}

	pcap_close(pcap);
}
