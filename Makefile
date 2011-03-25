# ifstat2
# Robert Olsson 040130
#
CFLAGS=  -g -Os -D_GNU_SOURCE
CC=$(DIET) gcc

CFLAGS += -Wall -static

LIBS= -lm

CSRCS1=		ifstat2.c libnetlink.c

OBJECTS1=        $(CSRCS1:.c=.o)


.KEEP_STATE:

EXEC1=ifstat2

all:	$(EXEC1) 


$(EXEC1): $(OBJECTS1)
	 $(CC) $(CFLAGS) -o $(EXEC1) $(TARGET_ARCH) $(OBJECTS1) $(LIBS)

ifstat2-diet:	ifstat2.c libnetlink.c
	diet $(CC) $(CFLAGS) -c $(TARGET_ARCH) libnetlink.c
	diet $(CC) $(CFLAGS) -c $(TARGET_ARCH) ifstat2.c
	diet $(CC) $(CFLAGS) -o ifstat2-diet $(TARGET_ARCH) $(OBJECTS1) $(LIBS)
#


clean:
	rm -f $(OBJECTS1) $(EXEC1) core

floppy:
	tar cvf /dev/fd0 *.c *.h Makefile
