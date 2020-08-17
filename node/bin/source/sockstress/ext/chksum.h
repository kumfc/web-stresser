#ifndef _CHKSUM_H
# define CHKSUM_H

typedef struct __attribute__((packed)) ip_pseudo_t {
	uint32_t saddr;
	uint32_t daddr;
	uint8_t zero;
	uint8_t proto;
	uint16_t len;
} ip_pseudo_t; /* precalculated ip pseudo header read inside the tcp|udp areas for checksumming */

uint16_t do_ipchksum(const uint8_t * /* ptr */, size_t /* count */);

int ip_checksum(uint8_t *, size_t );

/* this is to make the pseudo header chksum()ing less work, and to avoid copying memory */
struct chksumv {
	const uint8_t *ptr;
	size_t len;
};

uint16_t do_ipchksumv(const struct chksumv * /* chksum struct array */, int /* # of structs */);

#endif
