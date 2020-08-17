include ./Makefile.inc

SRCS=arp.c attacks.c ext/chtbl.c ext/chksum.c getroutes.c ext/makepkt.c main.c misc.c ext/packet_slice.c payload.c ext/rbtree.c ext/xmalloc.c ochksum.c ext/xdelay.c
HDRS=$(SRCS:.c=.h) ext/packets.h
OBJS=$(SRCS:.c=.o)

OBJS += ext/gtod.o ext/tsc.o ext/sleep.o

PROGNAME=sockstress

CFLAGS += -DPROGNAME=\"$(PROGNAME)\"

all: $(PROGNAME)

$(PROGNAME): $(OBJS) $(HDRS) ext/patricia_trie/libpatricia.a
	$(CC) $(CFLAGS) -o $(PROGNAME) $(OBJS) $(LDFLAGS)

tests:

ext/patricia_trie/libpatricia.a:
	make -C ext/patricia_trie

install:
	@echo There is no install for this program

clean:
	rm -f $(PROGNAME) $(OBJS) core
	make -C ext/patricia_trie clean

distclean: clean
	rm -rf configure autom4te.cache config.status config.log Makefile config.h
