include ../../Makefile.inc

SRCS=patricia.c
OBJS=$(SRCS:.c=.o)

RANLIB ?= ranlib

LIB=libpatricia.a

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) cru $(LIB) $(OBJS)
	$(RANLIB) $(LIB)

demo: $(OBJS) demo.c
	$(CC) $(CFLAGS) -o demo demo.c $(OBJS)

clean:
	rm -f $(LIB) $(OBJS) demo
