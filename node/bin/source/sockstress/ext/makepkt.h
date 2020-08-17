#ifndef _MAKEPKT_H
# define _MAKEPKT_H

void makepkt_clear(void);
int makepkt_getbuf(size_t *, const uint8_t **);

int makepkt_build_udp(	uint16_t	/* local port           */,
			uint16_t	/* remote port          */,
			uint16_t	/* chksum               */,
			const uint8_t *	/* payload              */,
			size_t		/* payload size         */);

int makepkt_build_tcp(	uint16_t	/* local_port           */,
			uint16_t	/* remote port          */,
			uint16_t	/* chksum               */,
			uint32_t	/* seq                  */,
			uint32_t	/* ack seq              */,
			uint16_t	/* tcphdr flags         */,
			uint16_t	/* window_size          */,
			uint16_t	/* urgent pointer       */,
			const uint8_t *	/* tcpoptions           */,
			size_t		/* tcpoptions size      */,
			const uint8_t * /* payload              */,
			size_t		/* payload size         */);

int makepkt_build_ipv4(	uint8_t		/* TOS                  */,
			uint16_t	/* IPID			*/,
			uint16_t	/* frag			*/,
			uint8_t		/* TTL			*/,
			uint8_t		/* proto		*/,
			uint16_t	/* chksum		*/,
			uint32_t	/* source		*/,
			uint32_t	/* dest			*/,
			const uint8_t * /* ip options		*/,
			size_t		/* ip opt size		*/,
			const uint8_t *	/* payload		*/,
			size_t		/* payload size		*/);

int makepkt_build_arp(	uint16_t	/* hw format            */,
			uint16_t	/* proto format         */,
			uint8_t		/* hw addr len          */,
			uint8_t		/* proto len            */,
			uint16_t	/* opcode		*/,
			const uint8_t *	/* senders hw addr      */,
			const uint8_t * /* senders proto addr   */,
			const uint8_t * /* targets hw addr      */,
			const uint8_t * /* targets proto addr   */);

int makepkt_build_ethernet(uint8_t addrlen,
			const uint8_t * /* dest hwaddr          */,
			const uint8_t * /* src hwaddr           */,
			uint16_t type); 

#endif
