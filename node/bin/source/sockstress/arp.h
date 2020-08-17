#ifndef _ARP_H
# define _ARP_H

void arp_init(int /* size */);

int arp_request(const struct sockaddr * /* network address to ask about	*/,
		const struct sockaddr * /* my network address		*/,
		uint8_t *		/* my ethernet address		*/,
		uint8_t *		/* ethernet address reply	*/,
		pcap_t *		/* ll socket			*/
);

void arp_fini(void);

#endif
