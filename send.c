#include "send.h"
#include "checksum.h"

void sendForward(pcap_t* pcap, char* org_pkt, uint8_t* attMac, struct Hdr_len* hdr_len){

	char packet[4096];
	
	memcpy(packet, org_pkt, ETH_LEN + hdr_len->ip_len + hdr_len->tcp_len);
	
	
	struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
	struct libnet_ipv4_hdr* ipv4_hdr = (struct libnet_ipv4_hdr*)(packet+ETH_LEN);
	struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet+ETH_LEN + hdr_len->ip_len);
	
	
	// ETH_HDR
	memcpy(eth_hdr->ether_shost, attMac, 6);
	
	// IP_HDR
	ipv4_hdr->ip_len = htons(hdr_len->ip_len + hdr_len->tcp_len);
	ipv4_hdr->ip_sum = 0;
	ipv4_hdr->ip_sum = checksum((uint16_t*)ipv4_hdr, hdr_len->ip_len/2);
	
	// TCP_HDR
	tcp_hdr->th_seq = htonl(ntohl(tcp_hdr->th_seq) + hdr_len->tcp_data_len);
	tcp_hdr->th_flags = 0;
	tcp_hdr->th_flags |= TH_RST;
	tcp_hdr->th_flags |= TH_ACK;

	struct pseudo_header pse;
	pse.src = ipv4_hdr->ip_src;
	pse.dst = ipv4_hdr->ip_dst;
	pse.ph = 0;
    	pse.pro = IPPROTO_TCP;
    	pse.tcp_len = htons(hdr_len->tcp_len);
    	
 	tcp_hdr->th_sum = (~checksum((uint16_t*)&pse, 6));
 	tcp_hdr->th_sum = checksum((uint16_t*)tcp_hdr, hdr_len->tcp_len/2);
 	
 	
 	int res = pcap_sendpacket(pcap, (u_char*)packet, ETH_LEN + hdr_len->ip_len + hdr_len->tcp_len);


}

void sendBackward(int sockfd, char* org_pkt, uint8_t* attMac, struct Hdr_len* hdr_len){

	const char* warn = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr/\r\n\r\n\0";
	char packet[4096];
	
	memcpy(packet, org_pkt+ETH_LEN, hdr_len->ip_len + hdr_len->tcp_len);
	memcpy(packet + hdr_len->ip_len + hdr_len->tcp_len, warn, strlen(warn));
	
	struct libnet_ipv4_hdr* ipv4_hdr = (struct libnet_ipv4_hdr*)packet;
	struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + hdr_len->ip_len);
	
	// Socket Setting
	struct sockaddr_in dest_addr;
	dest_addr.sin_family = AF_INET;
    	dest_addr.sin_port = tcp_hdr->th_sport;
    	dest_addr.sin_addr.s_addr = ipv4_hdr->ip_src;
    	
    	// IP_HDR
    	uint32_t tmp = ipv4_hdr->ip_src;
    	ipv4_hdr->ip_src = ipv4_hdr->ip_dst;
    	ipv4_hdr->ip_dst = tmp;
    	ipv4_hdr->ip_ttl = 128;
    	ipv4_hdr->ip_len = htons(hdr_len->tcp_len + hdr_len->ip_len + strlen(warn));
    	ipv4_hdr->ip_sum = 0;
    	ipv4_hdr->ip_sum = checksum((uint16_t*)ipv4_hdr, hdr_len->ip_len/2);
    	
    	// TCP_HDR
    	uint32_t ttmp = tcp_hdr->th_ack;
    	tcp_hdr->th_ack = htonl(ntohl(tcp_hdr->th_seq) + hdr_len->tcp_data_len);
    	tcp_hdr->th_seq = ttmp;
	tcp_hdr->th_flags = 0;
	tcp_hdr->th_flags |= TH_FIN;
	tcp_hdr->th_flags |= TH_ACK;
	tmp = tcp_hdr->th_sport;
	tcp_hdr->th_sport = tcp_hdr->th_dport;
	tcp_hdr->th_dport = tmp;

	struct pseudo_header pse;
	pse.src = ipv4_hdr->ip_src;
	pse.dst = ipv4_hdr->ip_dst;
	pse.ph = 0;
    	pse.pro = IPPROTO_TCP;
    	pse.tcp_len = htons(hdr_len->tcp_len + strlen(warn));
    	
 	tcp_hdr->th_sum = (~checksum((uint16_t*)&pse, 6));
 	tcp_hdr->th_sum = checksum((uint16_t*)tcp_hdr, (hdr_len->tcp_len+strlen(warn))/2);
    	
    				
    	int ret = sendto(sockfd, packet, hdr_len->tcp_len + hdr_len->ip_len + strlen(warn), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));


}
