#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef uint32_t ip_addr_t;

struct ip_hdr {
#ifndef BIGENDIAN
 uint8_t ip_hl:4,
   ip_v:4;
#else
 uint8_t ip_v:4,
   ip_hl:4;
#endif
 uint8_t ip_tos;
 uint16_t ip_len;
 uint16_t ip_id;
 uint16_t ip_off;
 uint8_t ip_ttl;
 uint8_t ip_p;
 uint16_t ip_sum;
 ip_addr_t ip_src;
 ip_addr_t ip_dst;
};

typedef struct ip_handle ip_t;

ip_t *ip_open(void);
ssize_t ip_send(ip_t *i, const void *buf, size_t len);
ip_t *ip_close(ip_t *i);

char *ip_ntop(const ip_addr_t *ip, char *dst, size_t len);
int ip_pton(const char *src, ip_addr_t *dst);
char *ip_ntoa(const ip_addr_t *ip);


ssize_t ip_add_option(void *buf, size_t len,
     int proto, const void *optbuf, size_t optlen);
void ip_checksum(void *buf, size_t len);

int ip_cksum_add(const void *buf, size_t len, int cksum);



typedef struct ip6_addr {
 uint8_t data[16];
} ip6_addr_t;
struct ip6_hdr {
 union {
  struct ip6_hdr_ctl {
   uint32_t ip6_un1_flow;
   uint16_t ip6_un1_plen;
   uint8_t ip6_un1_nxt;
   uint8_t ip6_un1_hlim;
  } ip6_un1;
  uint8_t ip6_un2_vfc;
 } ip6_ctlun;
 ip6_addr_t ip6_src;
 ip6_addr_t ip6_dst;
} __attribute__((__packed__));
struct ip6_ext_data_routing {
 uint8_t type;
 uint8_t segleft;

} __attribute__((__packed__));

struct ip6_ext_data_routing0 {
 uint8_t type;
 uint8_t segleft;
 uint8_t reserved;
 uint8_t slmap[3];
 ip6_addr_t addr[1];
} __attribute__((__packed__));




struct ip6_ext_data_fragment {
 uint16_t offlg;
 uint32_t ident;
} __attribute__((__packed__));
struct ip6_ext_hdr {
 uint8_t ext_nxt;
 uint8_t ext_len;
 union {
  struct ip6_ext_data_routing routing;
  struct ip6_ext_data_fragment fragment;
 } ext_data;
} __attribute__((__packed__));

char *ip6_ntop(const ip6_addr_t *ip6, char *dst, size_t size);
int ip6_pton(const char *src, ip6_addr_t *dst);
char *ip6_ntoa(const ip6_addr_t *ip6);


void ip6_checksum(void *buf, size_t len);

struct addr {
 uint16_t addr_type;
 uint16_t addr_bits;
 union {
  ip_addr_t __ip;
  ip6_addr_t __ip6;

  uint8_t __data8[16];
  uint16_t __data16[8];
  uint32_t __data32[4];
 } __addr_u;
};

int addr_cmp(const struct addr *a, const struct addr *b);

int addr_bcast(const struct addr *a, struct addr *b);
int addr_net(const struct addr *a, struct addr *b);

char *addr_ntop(const struct addr *src, char *dst, size_t size);
int addr_pton(const char *src, struct addr *dst);

char *addr_ntoa(const struct addr *a);


int addr_ntos(const struct addr *a, struct sockaddr *sa);
int addr_ston(const struct sockaddr *sa, struct addr *a);

int addr_btos(uint16_t bits, struct sockaddr *sa);
int addr_stob(const struct sockaddr *sa, uint16_t *bits);

int addr_btom(uint16_t bits, void *mask, size_t size);
int addr_mtob(const void *mask, size_t size, uint16_t *bits);

struct arp_hdr {
 uint16_t ar_hrd;
 uint16_t ar_pro;
 uint8_t ar_hln;
 uint8_t ar_pln;
 uint16_t ar_op;
};
struct arp_ethip {
 uint8_t ar_sha[6];
 uint8_t ar_spa[4];
 uint8_t ar_tha[6];
 uint8_t ar_tpa[4];
};




struct arp_entry {
 struct addr arp_pa;
 struct addr arp_ha;
};
typedef struct arp_handle arp_t;

typedef int (*arp_handler)(const struct arp_entry *entry, void *arg);


arp_t *arp_open(void);
int arp_add(arp_t *arp, const struct arp_entry *entry);
int arp_delete(arp_t *arp, const struct arp_entry *entry);
int arp_get(arp_t *arp, struct arp_entry *entry);
int arp_loop(arp_t *arp, arp_handler callback, void *arg);
arp_t *arp_close(arp_t *arp);

struct icmp_hdr {
 uint8_t icmp_type;
 uint8_t icmp_code;
 uint16_t icmp_cksum;
};
struct icmp_msg_echo {
 uint16_t icmp_id;
 uint16_t icmp_seq;
 uint8_t icmp_data [];
};




struct icmp_msg_needfrag {
 uint16_t icmp_void;
 uint16_t icmp_mtu;
 uint8_t icmp_ip [];
};





struct icmp_msg_quote {
 uint32_t icmp_void;


 uint8_t icmp_ip [];
};




struct icmp_msg_rtradvert {
 uint8_t icmp_num_addrs;
 uint8_t icmp_wpa;
 uint16_t icmp_lifetime;
 struct icmp_msg_rtr_data {
  uint32_t icmp_void;

  uint32_t icmp_pref;
 } icmp_rtr [];
};





struct icmp_msg_tstamp {
 uint32_t icmp_id;
 uint32_t icmp_seq;
 uint32_t icmp_ts_orig;
 uint32_t icmp_ts_rx;
 uint32_t icmp_ts_tx;
};




struct icmp_msg_mask {
 uint32_t icmp_id;
 uint32_t icmp_seq;
 uint32_t icmp_mask;
};




struct icmp_msg_traceroute {
 uint16_t icmp_id;
 uint16_t icmp_void;
 uint16_t icmp_ohc;
 uint16_t icmp_rhc;
 uint32_t icmp_speed;
 uint32_t icmp_mtu;
};




struct icmp_msg_dnsreply {
 uint16_t icmp_id;
 uint16_t icmp_seq;
 uint32_t icmp_ttl;
 uint8_t icmp_names [];
};




struct icmp_msg_idseq {
 uint16_t icmp_id;
 uint16_t icmp_seq;
};




union icmp_msg {
 struct icmp_msg_echo echo;
 struct icmp_msg_quote unreach;
 struct icmp_msg_needfrag needfrag;
 struct icmp_msg_quote srcquench;
 struct icmp_msg_quote redirect;
 uint32_t rtrsolicit;
 struct icmp_msg_rtradvert rtradvert;
 struct icmp_msg_quote timexceed;
 struct icmp_msg_quote paramprob;
 struct icmp_msg_tstamp tstamp;
 struct icmp_msg_idseq info;
 struct icmp_msg_mask mask;
 struct icmp_msg_traceroute traceroute;
 struct icmp_msg_idseq dns;
 struct icmp_msg_dnsreply dnsreply;
};
struct tcp_hdr {
 uint16_t th_sport;
 uint16_t th_dport;
 uint32_t th_seq;
 uint32_t th_ack;




 uint8_t th_x2:4,
   th_off:4;



 uint8_t th_flags;
 uint16_t th_win;
 uint16_t th_sum;
 uint16_t th_urp;
};
struct tcp_opt {
 uint8_t opt_type;
 uint8_t opt_len;
 union tcp_opt_data {
  uint16_t mss;
  uint8_t wscale;
  uint16_t sack[19];
  uint32_t echo;
  uint32_t timestamp[2];
  uint32_t cc;
  uint8_t cksum;
  uint8_t md5[16];
  uint8_t data8[40 - 2];
 } opt_data;
} __attribute__((__packed__));
struct udp_hdr {
 uint16_t uh_sport;
 uint16_t uh_dport;
 uint16_t uh_ulen;
 uint16_t uh_sum;
};

struct intf_entry {
 u_int intf_len;
 char intf_name[16];
 u_short intf_type;
 u_short intf_flags;
 u_int intf_mtu;
 struct addr intf_addr;
 struct addr intf_dst_addr;
 struct addr intf_link_addr;
 u_int intf_alias_num;
 struct addr intf_alias_addrs [];
};
typedef struct intf_handle intf_t;

typedef int (*intf_handler)(const struct intf_entry *entry, void *arg);


intf_t *intf_open(void);
int intf_get(intf_t *i, struct intf_entry *entry);
int intf_get_src(intf_t *i, struct intf_entry *entry, struct addr *src);
int intf_get_dst(intf_t *i, struct intf_entry *entry, struct addr *dst);
int intf_set(intf_t *i, const struct intf_entry *entry);
int intf_loop(intf_t *i, intf_handler callback, void *arg);
intf_t *intf_close(intf_t *i);

struct route_entry {
 struct addr route_dst;
 struct addr route_gw;
};

typedef struct route_handle route_t;

typedef int (*route_handler)(const struct route_entry *entry, void *arg);


route_t *route_open(void);
int route_add(route_t *r, const struct route_entry *entry);
int route_delete(route_t *r, const struct route_entry *entry);
int route_get(route_t *r, struct route_entry *entry);
int route_loop(route_t *r, route_handler callback, void *arg);
route_t *route_close(route_t *r);

struct fw_rule {
 char fw_device[16];
 uint8_t fw_op;
 uint8_t fw_dir;
 uint8_t fw_proto;
 struct addr fw_src;
 struct addr fw_dst;
 uint16_t fw_sport[2];
 uint16_t fw_dport[2];
};
typedef struct fw_handle fw_t;

typedef int (*fw_handler)(const struct fw_rule *rule, void *arg);


fw_t *fw_open(void);
int fw_add(fw_t *f, const struct fw_rule *rule);
int fw_delete(fw_t *f, const struct fw_rule *rule);
int fw_loop(fw_t *f, fw_handler callback, void *arg);
fw_t *fw_close(fw_t *f);

typedef struct tun tun_t;


tun_t *tun_open(struct addr *src, struct addr *dst, int mtu);
int tun_fileno(tun_t *tun);
const char *tun_name(tun_t *tun);
ssize_t tun_send(tun_t *tun, const void *buf, size_t size);
ssize_t tun_recv(tun_t *tun, void *buf, size_t size);
tun_t *tun_close(tun_t *tun);


typedef struct blob {
 u_char *base;
 int off;
 int end;
 int size;
} blob_t;


blob_t *blob_new(void);

int blob_read(blob_t *b, void *buf, int len);
int blob_write(blob_t *b, const void *buf, int len);

int blob_seek(blob_t *b, int off, int whence);






int blob_index(blob_t *b, const void *buf, int len);
int blob_rindex(blob_t *b, const void *buf, int len);

int blob_pack(blob_t *b, const char *fmt, ...);
int blob_unpack(blob_t *b, const char *fmt, ...);

int blob_insert(blob_t *b, const void *buf, int len);
int blob_delete(blob_t *b, void *buf, int len);

int blob_print(blob_t *b, char *style, int len);

blob_t *blob_free(blob_t *b);

int blob_register_alloc(size_t size, void *(*bmalloc)(size_t),
     void (*bfree)(void *), void *(*brealloc)(void *, size_t));






typedef struct rand_handle rand_t;


rand_t *rand_open(void);

int rand_get(rand_t *r, void *buf, size_t len);
int rand_set(rand_t *r, const void *seed, size_t len);
int rand_add(rand_t *r, const void *buf, size_t len);

uint8_t rand_uint8(rand_t *r);
uint16_t rand_uint16(rand_t *r);
uint32_t rand_uint32(rand_t *r);

int rand_shuffle(rand_t *r, void *base, size_t nmemb, size_t size);

rand_t *rand_close(rand_t *r);


void
ip_checksum(void *buf, size_t len)
{
 struct ip_hdr *ip;
 int hl, off, sum;

 if (len < 20)
  return;

 ip = (struct ip_hdr *)buf;
 hl = ip->ip_hl << 2;
 ip->ip_sum = 0;
 sum = ip_cksum_add(ip, hl, 0);
 ip->ip_sum = (sum = (sum >> 16) + (sum & 0xffff), (~(sum + (sum >> 16)) & 0xffff));

 off = htons(ip->ip_off);

 if ((off & 0x1fff) != 0 || (off & 0x2000) != 0)
  return;

 len -= hl;

 if (ip->ip_p == 6) {
  struct tcp_hdr *tcp = (struct tcp_hdr *)((u_char *)ip + hl);

  if (len >= 20) {
   tcp->th_sum = 0;
   sum = ip_cksum_add(tcp, len, 0) +
       htons(ip->ip_p + len);
   sum = ip_cksum_add(&ip->ip_src, 8, sum);
   tcp->th_sum = (sum = (sum >> 16) + (sum & 0xffff), (~(sum + (sum >> 16)) & 0xffff));
  }
 } else if (ip->ip_p == 17) {
  struct udp_hdr *udp = (struct udp_hdr *)((u_char *)ip + hl);

  if (len >= 8) {
   udp->uh_sum = 0;
   sum = ip_cksum_add(udp, len, 0) +
       htons(ip->ip_p + len);
   sum = ip_cksum_add(&ip->ip_src, 8, sum);
   udp->uh_sum = (sum = (sum >> 16) + (sum & 0xffff), (~(sum + (sum >> 16)) & 0xffff));
   if (!udp->uh_sum)
    udp->uh_sum = 0xffff;
  }
 } else if (ip->ip_p == 1 || ip->ip_p == 2) {
  struct icmp_hdr *icmp = (struct icmp_hdr *)((u_char *)ip + hl);

  if (len >= 4) {
   icmp->icmp_cksum = 0;
   sum = ip_cksum_add(icmp, len, 0);
   icmp->icmp_cksum = (sum = (sum >> 16) + (sum & 0xffff), (~(sum + (sum >> 16)) & 0xffff));
  }
 }
}

int
ip_cksum_add(const void *buf, size_t len, int cksum)
{
 uint16_t *sp = (uint16_t *)buf;
 int n, sn;

 sn = len / 2;
 n = (sn + 15) / 16;


 switch (sn % 16) {
 case 0: do {
  cksum += *sp++;
 case 15:
  cksum += *sp++;
 case 14:
  cksum += *sp++;
 case 13:
  cksum += *sp++;
 case 12:
  cksum += *sp++;
 case 11:
  cksum += *sp++;
 case 10:
  cksum += *sp++;
 case 9:
  cksum += *sp++;
 case 8:
  cksum += *sp++;
 case 7:
  cksum += *sp++;
 case 6:
  cksum += *sp++;
 case 5:
  cksum += *sp++;
 case 4:
  cksum += *sp++;
 case 3:
  cksum += *sp++;
 case 2:
  cksum += *sp++;
 case 1:
  cksum += *sp++;
  } while (--n > 0);
 }
 if (len & 1)
  cksum += htons(*(u_char *)sp << 8);

 return (cksum);
}
