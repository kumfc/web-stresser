/* config.h.  Generated from config.h.in by configure.  */
#ifndef _CONFIG_H
# define _CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/route.h>

#include <pcap.h>

extern int verbose;

#define INT_NTOA(x)     inet_ntoa(*((struct in_addr *)&x))

#define DBG(msg, args...)\
	if (verbose > 4) {\
		fprintf(stderr, "[%%] DEBUG %s:%u: " msg "\n", __FILE__, __LINE__, ## args);\
	}

#define ERR(msg, args...)\
	fprintf(stderr, "[-] ERROR %s:%u: " msg "\n", __FILE__, __LINE__, ## args);

#define assert(f) \
	if (! ( f ) ) { \
		PANIC("[-] Assertion `%s' fails", # f); \
	}

#define PANIC(fmt, args...) \
	do { \
		\
		fprintf(stderr, "[-] PANIC at %s:%u " fmt "\n", __FILE__, __LINE__,  ## args); \
		if (verbose > 4) { \
			fprintf(stderr, "[@] Attach to pid %d , called from %s() %s:%d\n", getpid(), __FUNCTION__, __FILE__, __LINE__); \
			pause(); \
		} \
		abort(); \
	} while (0)

#define MIN(x, y) \
	((x) < (y) ? (x) : (y))

/* #undef HAVE_STRUCT_SOCKADDR_LEN */

#define DEF_ARPTBL_SIZE	1024
#define DEF_WINDOW_SIZE 0x16d0
#define DEF_RPORT	80
#define DEF_RPORT_STR	"80"
#define DEF_MAX_CONNS	100
#define DEF_MAX_SYNS	200
#define DEF_USLEEP_TIME	1000
#define TICK_HZ		1024

#ifdef HAVE_STRUCT_SOCKADDR_LEN
struct f_s {
	uint8_t len;
	uint8_t family;
};
#else
struct f_s {
	uint16_t family;
};
#endif

typedef union sa_u {
	struct f_s *fs;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct sockaddr_storage *ss;
	struct sockaddr *s;
	struct sockaddr_ll *sl;
} sa_u;

typedef union isa_u {
	const struct f_s *fs;
	const struct sockaddr_in *sin;
	const struct sockaddr_in6 *sin6;
	const struct sockaddr_storage *ss;
	const struct sockaddr *s;
	const struct sockaddr_ll *sl;
} isa_u;


#define STFMT	"%zu"

#endif
