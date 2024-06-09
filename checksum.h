#include <stdint.h>

uint16_t checksum(uint16_t *buf, uint8_t len){

	uint32_t sum = 0;
	
	int i;
	for(i=0; i < len; i++){
		sum += ntohs(*buf);
		buf++;
	}
	
	sum = (sum >> 16) + (sum&0xffff);
	sum += (sum >> 16);
	sum ^= 0xffff;
	
	return htons((uint16_t)(sum));

}
