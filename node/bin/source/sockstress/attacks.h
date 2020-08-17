#ifndef _ATTACKS_H
# define _ATTACKS_H

extern uint16_t mywindow;

void init_attacks(void);

void do_0window_stress(
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

void do_smlwnd_stress(
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

void do_ooseg_stress(
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

void do_sillyface_stress(
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

void do_enablereno_stress(
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

#endif
