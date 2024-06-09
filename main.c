#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>

#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>

#include "ess_func.h"
#include "send.h"

#define ETH_LEN 14
#define IPV4_LEN 20
#define TCP_LEN 20

const char* warn = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr/\r\n\r\n\0";

void usage() {
	printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

typedef struct {
	char* dev_;
	char* pattern_;
} Param;
Param param;


bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	param->pattern_ = argv[2];
	return true;
}


int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;
		
	struct Hdr_len hdr_len;
	uint8_t attMac[6];
	GetMacAddr(argv[1], attMac);
	
	
	// RAW SOCKET OPEN
	int sockfd;
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) {
		perror("socket");
	return -1;
    	}
    				
    	int value = 1;
	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (char *)&value, sizeof(value)) < 0){
		perror("setsockopt");
        	close(sockfd);
        	return -1;
        }
        

	// PCAP OPEN
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
	
		struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;

		if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP){
		
			struct libnet_ipv4_hdr* ipv4_hdr = (struct libnet_ipv4_hdr*)(eth_hdr+1);
			uint16_t ipv4_hdr_len = 4*(ipv4_hdr->ip_hl);
	
			if(ipv4_hdr->ip_p == IPTYPE_TCP){
				
				struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)((char*)ipv4_hdr + ipv4_hdr_len);
				uint16_t tcp_hdr_len = 4*tcp_hdr->th_off;
				
				uint32_t payload_len = ntohs(ipv4_hdr->ip_len) - ipv4_hdr_len - tcp_hdr_len;
				
				if(payload_len < strlen(param.pattern_)) continue;
				
				char* tcp_data = (char*)tcp_hdr + tcp_hdr_len;
				
				char* isPatternEx = strnstr(tcp_data, param.pattern_, payload_len);
				if(isPatternEx == NULL) continue;
				
				
				// Pattern!
				
				hdr_len.ip_len = ipv4_hdr_len;
				hdr_len.tcp_len = tcp_hdr_len;
				hdr_len.tcp_data_len = payload_len;
				
				sendForward(pcap, (char*)packet, attMac, &hdr_len);
				sendBackward(sockfd, (char*)packet, attMac, &hdr_len);
				
			}
			
		}

	}

	pcap_close(pcap);
}
