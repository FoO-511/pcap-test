#include "net_headers.h"

void print_uchar_as_hex(u_char *array, int len){
    for (int i = 0; i < len; i++){ 
        printf("%02X ", (unsigned int)(array[i]) & 0xFF); 
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}


/*
Ethernet
*/
void print_ether_mac(u_char *array){
    for (int i = 0; i < ETHER_ADDR_LEN; i++){ 
        printf("%02X", (unsigned int)(array[i]) & 0xFF);
        if(i!=ETHER_ADDR_LEN-1){printf(":");}        
    }
    printf("\n");
}


void print_ether_macs(my_ether_hdr ether_hdr){
    printf("dst mac : "); print_ether_mac((u_char *)&ether_hdr.des_mac);
    printf("src mac : "); print_ether_mac((u_char *)&ether_hdr.src_mac);
}


/*
IP
*/
void print_ip_addr(u_char *array){
    for (int i = 0; i < IP_ADDR_LEN; i++){ 
        printf("%d", (unsigned int)(array[i]) & 0xFF);
        if(i!=IP_ADDR_LEN-1){printf(".");}        
    }
    printf("\n");
}


void print_ip_addrs(my_ip_hdr ip_hdr){
    printf("ip src : "); print_ip_addr((u_char *)&ip_hdr.src_addr);
    printf("ip des : "); print_ip_addr((u_char *)&ip_hdr.des_addr);
}


void print_ip_info(my_ip_hdr ip_hdr){
    printf("-----[IP HEADER]-----\n");
    printf("version: 0x%x \n",ip_hdr.version);
    printf("header length: 0x%x * 4 = %d Bytes\n",ip_hdr.hdr_len, ip_hdr.hdr_len *4);
    printf("type of service: 0x%x \n",ip_hdr.type_of_service);
    printf("total length: 0x%x = %d \n",ntohs(ip_hdr.total_length), ntohs(ip_hdr.total_length));
    printf("id: 0x%x \n",ip_hdr.id);
    printf("flag x: 0x%x \n",ip_hdr.flag_x);
    printf("flag D: 0x%x \n",ip_hdr.flag_D);
    printf("flag M: 0x%x \n",ip_hdr.flag_M);
    printf("fragment offset: 0x%x \n",ip_hdr.frag_offset);
    printf("time to live: 0x%x = %d \n",ip_hdr.time_to_live, ip_hdr.time_to_live);
    printf("protocol: 0x%02x",ip_hdr.protocol); if (ip_hdr.protocol==6){printf(" (tcp) ");} printf("\n");
    printf("header checksum: 0x%x\n",ip_hdr.hdr_checksum);
    print_ip_addrs(ip_hdr);
    printf("------------------\n");
}


/*
TCP
*/
void print_tcp_ports(my_tcp_hdr tcp_hdr){
    printf("src port : %d\n", ntohs(tcp_hdr.src_port));
    printf("des port : %d\n", ntohs(tcp_hdr.des_port));
}


void print_tcp_flags(my_tcp_hdr tcp_hdr){
    printf("zeros: %03x\t", tcp_hdr.zeros);
    printf("NS: %x\t", tcp_hdr.NS);
    printf("CWR: %x\t", tcp_hdr.CWR);
    printf("ECE: %x\t", tcp_hdr.ECE);
    printf("URG: %x\t", tcp_hdr.URG);
    printf("ACK: %x\t", tcp_hdr.ACK);
    printf("PSH: %x\t", tcp_hdr.PSH);
    printf("RST: %x\t", tcp_hdr.RST);
    printf("SYN: %x\t", tcp_hdr.SYN);
    printf("FIN: %x\n", tcp_hdr.FIN);
}


void print_tcp_info(my_tcp_hdr tcp_hdr){
    printf("---[TCP HEADER]---\n");
    print_tcp_ports(tcp_hdr);
    printf("sequence number: %d\n", ntohl(tcp_hdr.seq_num));
    printf("acknowledgement number: %d\n", ntohl(tcp_hdr.ack_num));
    
    printf("data offset: 0x%x * 4 = %d Bytes.\n", tcp_hdr.data_offset, tcp_hdr.data_offset * 4);
    printf("options length: %d - 20 = %d Bytes \n", tcp_hdr.data_offset * 4, tcp_hdr.data_offset * 4 -20);

    print_tcp_flags(tcp_hdr);

    printf("window size: %d\n", ntohs(tcp_hdr.window_size));
    printf("checksum: 0x%04x\n", ntohs(tcp_hdr.checksum));
    printf("urgent_pointer: 0x%04x\n", ntohs(tcp_hdr.urgent_pointer));

    printf("------------------\n");
}

