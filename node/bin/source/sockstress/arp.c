#include "config.h"
#include "ext/chtbl.h"
#include "ext/makepkt.h"
#include "ext/packets.h"
#include "ext/packet_slice.h"
#include "ext/xmalloc.h"
#include "main.h"

#include "arp.h"

static void *arptbl=NULL;
static int timedout=0, gotresp=0;
static char *strmac(const uint8_t *);
static uint32_t _a_myip=0;
static uint8_t *_a_mymac=NULL;
static uint8_t *_a_dmac=NULL;
static uint32_t _a_dip=0;

void arp_init(int size) {
	arptbl=chtinit(size);

	return;
}

void arp_fini(void) {
	chtdestroy(arptbl);

	return;
}

static void arp_tmout(int signo) {
	timedout++;
}

static void arp_procresp(uint8_t *userdata, const struct pcap_pkthdr *phdr, const uint8_t *packet) {
	union {
		const struct myetherarphdr *ea;
		const struct my6etherheader *e;
		const uint8_t *p;
	} p_u;
	size_t pl_sz=0, packet_len=0, j=0, plz_len=0;
	packetlayers_t plz[8];

	assert(phdr != NULL && packet != NULL);

	packet_len=phdr->caplen;

	pl_sz=packet_slice(packet, packet_len, plz, 8, PKLTYPE_ETH);

	for (j=0; j < MIN(pl_sz, 8); j++) {
		DBG("layer `%zu' stat %s and type %s", j, strpkstat(plz[j].stat), strpklayer(plz[j].type));
		
		p_u.p=plz[j].ptr;
		plz_len=plz[j].len;

		switch (plz[j].type) {
			case PKLTYPE_ETH:
				assert(plz_len >= sizeof(struct my6etherheader));
				break;

			case PKLTYPE_EARP:
				assert(plz_len >= sizeof(struct myetherarphdr));
				if (ntohs(p_u.ea->opcode) != 2 || ntohs(p_u.ea->hw_type) != 1 || p_u.ea->hwsize != 6 || p_u.ea->protosize != 4) {
					break;
				}
				if (p_u.ea->sip == _a_dip && p_u.ea->dip == _a_myip && memcmp(p_u.ea->dmac, _a_mymac, 6) == 0) {
					gotresp=1;
					DBG("pktsource `%s'", INT_NTOA(p_u.ea->sip));
					DBG("pktdest   `%s'", INT_NTOA(p_u.ea->dip));
					DBG("pktsmac   `%s'", strmac(p_u.ea->smac));
					DBG("pktdmac   `%s'", strmac(p_u.ea->dmac));
					DBG("myip      `%s'", INT_NTOA(_a_myip));
					DBG("dip       `%s'", INT_NTOA(_a_dip));
					DBG("mymac     `%s'", strmac(_a_mymac));
					DBG("dmac      `%s'", strmac(_a_dmac));
				}
				memcpy(_a_dmac, p_u.ea->smac, 6);

				break;

			case PKLTYPE_JUNK:
				break;
			default:
				ERR("strange packet layer type %s", strpklayer(plz[j].type));
				return;
		}
	}
}

int arp_request(const struct sockaddr *dest, const struct sockaddr *me, uint8_t *mymac, uint8_t *destmac, pcap_t *p) {
	isa_u d_u, m_u;
	const uint8_t ebc[6]={0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, abc[6]={0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	const uint8_t *pkt=NULL;
	int tries=0;
	struct bpf_program bp;
	size_t pkt_len=0;
	uint32_t addrfix=0;
	union {
		uint8_t *mac;
		void *p;
	} c_u;

	assert(dest != NULL && me != NULL && destmac != NULL && p != NULL);

	d_u.s=dest;
	m_u.s=me;
	if (d_u.sin->sin_family != AF_INET || d_u.sin->sin_family != AF_INET) {
		ERR("im lazy");
		return -1;
	}

	addrfix=htonl(m_u.sin->sin_addr.s_addr);

	_a_myip=addrfix;
	_a_mymac=mymac;
	_a_dmac=destmac;
	_a_dip=d_u.sin->sin_addr.s_addr;

	if (chtfind(arptbl, _a_dip, &c_u.p) == 1) {
		ERR("cache hit!!!");
		memcpy(destmac, c_u.p, 6);
		return 1;
	}

	if (pcap_compile(p, &bp, "arp", 0, intf_net) < 0) {
		ERR("cant compile pcap filter `arp'");
		return -1;
	}

	if (pcap_setfilter(p, &bp) < 0) {
		ERR("cant set pcap filter");
		return -1;
	}

	pcap_freecode(&bp);
	
	if (pcap_setnonblock(p, 1, pcap_errors) < 0) {
		ERR("cant set pcap device non-blocking!");
		return -1;
		
	}

	for (tries=0; tries < 1; tries++) {
		/*
		 * create our arp request
		 */
		makepkt_clear();

		makepkt_build_ethernet(
				6,
				ebc,
				(const uint8_t *)mymac,
				ETHERTYPE_ARP
		);

		makepkt_build_arp(
				ARPHRD_ETHER,
				ETHERTYPE_IP,
				6,
				4,
				ARPOP_REQUEST,
				(const uint8_t *)mymac,
				(const uint8_t *)&addrfix,
				abc,
				(const uint8_t *)&d_u.sin->sin_addr.s_addr
		);

		makepkt_getbuf(&pkt_len, &pkt);
		if (pkt == NULL || pkt_len < 1) {
			ERR("makepkt_getbuf fails with no data");
			return -1;
		}

		if (pcap_sendpacket(p, pkt, pkt_len) != 0) {
			ERR("cant send arp request");
			return -1;
		}

		timedout=0;
		signal(SIGALRM, arp_tmout);
		alarm(1);

		for (gotresp=0; timedout == 0; ) {
			pcap_dispatch(p, -1, &arp_procresp, NULL);
			if (gotresp) {
				alarm(0);
				break;
			}
			usleep(10000);
		}

		if (gotresp) {
			break;
		}
	}

	if (pcap_setnonblock(p, 0, pcap_errors) < 0) {
		ERR("cant set pcap device non-blocking!");
		return -1;
		
	}

	if (gotresp == 1) {
		uint8_t *cp=NULL;

		cp=xmalloc(6);
		memcpy(cp, destmac, 6);

		if (chtinsert(arptbl, _a_dip, cp) != 1) {
			ERR("got mac but cannot cache it");
		}

		return 1;
	}
	return -1;
}

static char *strmac(const uint8_t *maddr) {
	static char mac[64];

	snprintf(mac, sizeof(mac) - 1, "%02x:%02x:%02x:%02x:%02x:%02x", maddr[0], maddr[1], maddr[2], maddr[3], maddr[4], maddr[5]);

	return mac;
}
