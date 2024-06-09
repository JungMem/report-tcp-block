#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdlib.h>

char *strnstr(const char *haystack, const char *needle, size_t len) {
    size_t needle_len;

    if (*needle == '\0') {
        return (char *)haystack;
    }

    needle_len = 0;
    while (needle[needle_len] != '\0') {
        needle_len++;
    }

    for (size_t i = 0; i <= len - needle_len; i++) {
        if (haystack[i] == '\0') {
            break;
        }
        if (haystack[i] == needle[0] && 
            strncmp(&haystack[i], needle, needle_len) == 0) {
            return (char *)&haystack[i];
        }
    }

    return NULL;
}

void GetMacAddr(const char *ifname, uint8_t *mac_addr){

	struct ifreq ifr;
	int sockfd, ret;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0){
		printf("Faile to get interface MAC address - socket() failed - %m\n");
		exit(1);
	}
	
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if(ret <0){
		printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
		close(sockfd);
		exit(1);
	}
	
	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
	close(sockfd);
	
}
