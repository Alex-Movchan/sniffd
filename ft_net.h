#ifndef FT_NET_H
#define FT_NET_H

#include <stdint.h>

#if !defined(__LITTLE_ENDIAN__) && !defined(__BIG_ENDIAN__) && defined(__BYTE_ORDER)

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define __LITTLE_ENDIAN__
#elif __BYTE_ORDER == __BIG_ENDIAN
#define __BIG_ENDIAN__
#endif

#endif

/* Octets in ethernet address */
#define ETH_ALEN 6

struct ethhdr
{
	unsigned char h_dest[ETH_ALEN];
	unsigned char h_source[ETH_ALEN];
	/* packet type ID */
	uint16_t      h_proto;
} __attribute__((packed));


struct iphdr
{

#if defined(__LITTLE_ENDIAN__)

	uint8_t  ihl:4,
           version:4;

#elif defined (__BIG_ENDIAN__)

	uint8_t  version:4,
           ihl:4;

#else

#endif

	uint8_t  tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t  ttl;
	uint8_t  protocol;
	uint16_t check;
	uint32_t saddr;
	uint32_t daddr;
} __attribute__((packed));



#endif
