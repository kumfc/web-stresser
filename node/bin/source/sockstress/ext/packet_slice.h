#ifndef _PACKETSLICE_H
# define _PACKETSLICE_H

typedef struct packetlayers_t {
	uint8_t type;
#define PKLTYPE_ETH		1
#define PKLTYPE_ARP		2
#define PKLTYPE_EARP		3
#define PKLTYPE_IP		4
#define PKLTYPE_IPO		5
#define PKLTYPE_UDP		6
#define PKLTYPE_TCP		7
#define PKLTYPE_TCPOP		8
#define PKLTYPE_ICMP		9
#define PKLTYPE_PAYLOAD		10
#define PKLTYPE_JUNK		11

	uint8_t stat;
#define PKLSTAT_DMGED		1
#define PKLSTAT_TRUNC		2
#define PKLSTAT_LAST		3
#define PKLSTAT_UNSUP		4

	const uint8_t *ptr;
	size_t len;
} packetlayers_t;

size_t packet_slice(const uint8_t * /* packet */, size_t /* of packet */,
		    packetlayers_t * /* already allocated */, size_t /* sizeof struct packetlayers */,
		    int /* layer start ie PKLTYPE_IP */);

char *strpklayer(int /* PKLTYPE_? */);
char *strpkstat(int /* stat */);
#endif
