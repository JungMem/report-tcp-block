#include <string.h>
#include <pcap.h>
#include <stdint.h>

#include "ess_libnet.h"

void sendForward(pcap_t* pcap, char* org_pkt, uint8_t* attMac, struct Hdr_len* hdr_len);
void sendBackward(int sockfd, char* org_pkt, uint8_t* attMac, struct Hdr_len* hdr_len);
