ARCH := $(shell uname -m)
X64 = x86_64
PROGS = mqagent

LIBS = -levent -lm $(shell pkg-config --libs glib-2.0)

CFLAGS = -Wall -g -O2 `pkg-config --cflags glib-2.0`

all: $(PROGS)

STPROG = mqagent.o ketama.o glib-ext.o glibconf.o log.o mqagent_lib.o 

mqagent: $(STPROG) 
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
mqagent.o: mqagent.c glib-ext.h log.h mqagent.h config.h mqagent_lib.h
	$(CC) $(CFLAGS) -c -o $@ mqagent.c
ketama.o: ketama.c ketama.h
	$(CC) $(CFLAGS) -c -o $@ ketama.c
glib-ext.o: glib-ext.c glib-ext.h sys-pedantic.h
	$(CC) $(CFLAGS) -c -o $@ glib-ext.c
glibconf.o: glibconf.c config.h
	$(CC) $(CFLAGS) -c -o $@ glibconf.c
log.o: log.c log.h
	$(CC) $(CFLAGS) -c -o $@ log.c
mqagent_lib.o: mqagent_lib.c mqagent.h config.h mqagent.h
	$(CC) $(CFLAGS) -c -o $@ mqagent_lib.c

install:
	cp  mqagent /opt/mqagent/bin/

clean: 
	rm -f *.o *~ $(PROGS)
