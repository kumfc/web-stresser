#ifndef _MAIN_H
# define _MAIN_H

#define MAX_FUNC_LIST_SIZE	128

typedef struct func_list_t {
	const char *name;
	char opt;
	void (*fp)(uint32_t, uint32_t, uint16_t, uint16_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, int);
} func_list_t;

extern char pcap_errors[];
extern uint32_t intf_net, intf_mask;
extern uint8_t delay_type;
extern void update_tickcnt(void);

extern uint32_t tickcnt;
extern uint8_t gwmac[6], ea[6];
extern pcap_t *pdev;
extern unsigned int connections, max_conns;

extern func_list_t **fl;
extern unsigned int fl_off;

#endif
