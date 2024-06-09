#include <stdint.h>

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20

#define TCP_LEN 20
#define IP_LEN 20
#define ETH_LEN 14

#define ETHERTYPE_IP            0x0800  /* IP protocol */
#define IPTYPE_TCP		0x06    /* TCP Protocol */

struct pseudo_header{
        uint32_t src;
       	uint32_t dst;
       	uint8_t ph;
       	uint8_t pro;
       	uint16_t tcp_len;
};

struct Hdr_len{
	uint32_t ip_len;
	uint32_t tcp_len;
	uint32_t tcp_data_len;
};

/*
 *  Ethernet II header
 *  Static header size: 14 bytes
 */
struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[6];             /* destination ethernet address */
    u_int8_t  ether_shost[6];             /* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};


/*
 *  IPv4 header
 *  Internet Protocol, version 4
 *  Static header size: 20 bytes
 */
struct libnet_ipv4_hdr
{

    u_int8_t ip_hl:4,       /* version */
           ip_v:4;        /* header length */

    u_int8_t ip_tos;       /* type of service */

    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;

    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    
    u_int32_t ip_src;	      /* src ip */
    u_int32_t ip_dst;         /* dst ip */
};

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04

/*
 *  TCP header
 *  Transmission Control Protocol
 *  Static header size: 20 bytes
 */
struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */

    u_int8_t th_x2:4,        /* data offset */
           th_off:4;         /* (unused) */

    u_int8_t  th_flags;       /* control flags */

    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};
