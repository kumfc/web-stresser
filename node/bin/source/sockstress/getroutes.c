#include "config.h"
#include "ext/xmalloc.h"
#include "arp.h"

#include "ext/patricia_trie/patricia.h"

static void get_netroutes(void);
static int masktocidr(uint32_t );

static int need_netroutes=1;
static patricia_tree_t *rt=NULL;
static patricia_node_t *node=NULL;

typedef union route_info_t {
	struct info_s {
		char *intf;
		uint16_t metric;
		uint16_t flags;
		struct sockaddr_storage gw;
	} *info_s;
	void *p;
} route_info_t;

int getroutes(char **intf, struct sockaddr *tgt, struct sockaddr **gw) {
	static char lookup[128];
	route_info_t ri_u;
	sa_u ts_u, gws_u;
	static struct sockaddr_storage gw_s;

	assert(intf != NULL && tgt != NULL && gw != NULL);

	ts_u.s=tgt;
	*gw=NULL;

	switch (ts_u.fs->family) {
		case AF_INET:
			sprintf(lookup, "%s/32", INT_NTOA(ts_u.sin->sin_addr.s_addr));
			break;
		default:
			ERR("unknown address family `%d'", ts_u.fs->family);
			return -1;
	}

	if (need_netroutes) {
		get_netroutes();
	}

	node=try_search_best(rt, lookup);
	if (node == NULL) {
		ERR("bad luck");
		*intf=NULL;
		*gw=NULL;
		return -1;
	}
	ri_u.p=node->data;
	assert(node->data != NULL);

	DBG("found interface `%s' for network `%s'", ri_u.info_s->intf, lookup);

	*intf=ri_u.info_s->intf;
	if (ri_u.info_s->gw.ss_family != 0) {
		memcpy(&gw_s, &ri_u.info_s->gw, sizeof(struct sockaddr_storage));
		gws_u.ss=&gw_s;
		*gw=gws_u.s;
	}
	else {
		*gw=NULL;
	}

	return 1;
}

static int masktocidr(uint32_t mask) {
	int j=0, cidr=0;

	/* endian */
	for (j=0; j < 32; j++) {
		if ((mask & 0x80000000) == 0x80000000) {
			cidr++;
		}
		mask <<= 1;
	}

	return cidr;
}

static void get_netroutes(void) {
	FILE *pnr=NULL;
	char lbuf[1024], intf[32];
	uint32_t dest, gw, refcnt, use, mask, irtt;
	uint16_t metric, flags, window, mtu;
	char destnet[128], gwstr[128], addstr[128];
	int lineno=0;

	pnr=fopen("/proc/net/route", "r");
	if (pnr == NULL) {
		ERR("cant open /proc/net/route: `%s'", strerror(errno));
		exit(1);
	}

	rt=New_Patricia(128);

	/*
	 * Iface   Destination     Gateway         Flags   RefCnt  Use     Metric  Mask            MTU     Window  IRTT
	 * eth1    0045A8C0        00000000        0001    0       0       0       00FFFFFF        0       0       0
	 */

	for (lineno=0; fgets(lbuf, sizeof(lbuf) -1, pnr) != NULL; lineno++) {
		if (lineno == 0) {
			continue;
		}
#if 0
#define RTF_UP          0x0001          /* route usable                 */
#define RTF_GATEWAY     0x0002          /* destination is a gateway     */
#define RTF_HOST        0x0004          /* host entry (net otherwise)   */
#define RTF_REINSTATE   0x0008          /* reinstate route after tmout  */
#define RTF_DYNAMIC     0x0010          /* created dyn. (by redirect)   */
#define RTF_MODIFIED    0x0020          /* modified dyn. (by redirect)  */
#define RTF_MTU         0x0040          /* specific MTU for this route  */
#define RTF_MSS         RTF_MTU         /* Compatibility :-(            */
#define RTF_WINDOW      0x0080          /* per route window clamping    */
#define RTF_IRTT        0x0100          /* Initial round trip time      */
#define RTF_REJECT      0x0200          /* Reject route                 */
#endif
		/*                 in  de gw fl  ref us me ma mt  wi  ir	*/
		if (sscanf(lbuf, "%31s %x %x %hx %u %u %hu %x %hu %hu %u", intf, &dest, &gw, &flags, &refcnt, &use, &metric, &mask, &mtu, &window, &irtt) == 11) {
			int mycidr=0;

			strcpy(destnet, INT_NTOA(dest));
			mycidr=masktocidr(mask);
			strcpy(gwstr, INT_NTOA(gw));

			if (flags & RTF_UP && mycidr > -1) {
				sa_u s_u;
				route_info_t ri_u;

				ri_u.p=xmalloc(sizeof(*ri_u.info_s));
				memset(ri_u.p, 0, sizeof(*ri_u.info_s));

				ri_u.info_s->intf=xstrdup(intf);
				ri_u.info_s->metric=metric; /* could only be 0xff anyhow */
				ri_u.info_s->flags=flags;
				if ((flags & RTF_GATEWAY) == RTF_GATEWAY) {
					s_u.ss=&ri_u.info_s->gw;
					s_u.sin->sin_addr.s_addr=gw;
					s_u.sin->sin_family=AF_INET;
				}

				sprintf(addstr, "%s/%d", destnet, mycidr);
				DBG("net %s via %s metric %u", addstr, (flags & RTF_GATEWAY) == 0 ? intf : gwstr, metric);
				node=make_and_lookup(rt, addstr);
				if (node == NULL) {
					exit(1);
				}
				node->data=ri_u.p;

			}
		}
		else {
			ERR("can not parse `%s'", lbuf);
		}
	}

	fclose(pnr);
	need_netroutes=0;

	return;
}
