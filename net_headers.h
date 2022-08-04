#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#pragma once

#define ETHER_HDR_LEN 20
#define ETHER_ADDR_LEN 6
#define IP_HDR_LEN 20
#define IP_ADDR_LEN 4

// u_int8_t = 8bit = 1byte
// u_int16_t = 16bit = 2byte

typedef struct {
    u_int8_t des_mac[ETHER_ADDR_LEN];
    u_int8_t src_mac[ETHER_ADDR_LEN];
    u_int16_t ether_type;
}my_ether_hdr;

typedef struct {
    // don't know why but version should go second.
    u_int8_t hdr_len:4; // search bitfields
    u_int8_t version:4;
    u_int8_t type_of_service; 
    u_int16_t total_length;
    u_int16_t id;
    u_int16_t flag_x:1, flag_D:1, flag_M:1, frag_offset:13;
    u_int8_t time_to_live;
    u_int8_t protocol;
    u_int16_t hdr_checksum;
    u_char src_addr[IP_ADDR_LEN];
    u_char des_addr[IP_ADDR_LEN];
    // struct in_addr ip_src, ip_dst; <- can't understand the code 
}my_ip_hdr;

typedef struct{
    u_int16_t src_port;
    u_int16_t des_port;
    u_int32_t seq_num;
    u_int32_t ack_num;
    u_int16_t data_offset:4, zeros:3, NS:1, CWR:1, ECE:1, URG:1, ACK:1, PSH:1, RST:1, SYN:1, FIN:1;
    u_int16_t window_size;
    u_int16_t checksum;
    u_int16_t urgent_pointer;
} my_tcp_hdr;

void print_uchar_as_hex(u_char* array, int len);

void print_ether_mac(u_char *array);
void print_ether_macs(my_ether_hdr ether_hdr);

void print_ip_info(my_ip_hdr ip_hdr);
void print_ip_addr(u_char *array);
void print_ip_addrs(my_ip_hdr ip_hdr);

void print_tcp_info(my_tcp_hdr tcp_hdr);
void print_tcp_ports(my_tcp_hdr tcp_hdr);
