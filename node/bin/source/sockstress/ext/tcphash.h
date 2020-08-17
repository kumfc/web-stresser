#ifndef _TCPHASH_H
# define _TCPHASH_H

/* compare unsigned sequence numbers with wrap correctly */
#define SEQ_LT(x, ref) \
	((int32_t )((x) - (ref)) < 0)

#define SEQ_GT(x, ref) \
	((int32_t )((ref) - (x)) < 0)

#define SEQ_WITHIN(x, low, high) \
	((int32_t)(high - x) >= (int32_t)(x - low))

#define TCPHASHTRACK(res_ptr, srcip, srcport, dstport, syncookie) \
	DBG("syncookie %08x srcip %08x srcport %04x dstport %04x", (syncookie), (srcip), (srcport), (dstport)); \
	res_ptr=((syncookie) ^ ((srcip) ^ ( ((srcport) << 16) + (dstport) )))

#endif
