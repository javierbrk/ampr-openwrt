#
# Makefile for ampr-ripd
#

CONFDIR = $(DESTDIR)/etc
SBINDIR = $(DESTDIR)/usr/sbin
SCACHEDIR = $(DESTDIR)/var/lib/amprd

CC = gcc
CFLAGS = -Wall -O2 
LD = gcc
LDFLAGS =

OBJFILES = amprd.o tunnel.o minIni.o list.o rip.o encap.o cache.o route.o callhome.o

.c.o:
	$(CC) $(CFLAGS) -c $<

amprd:	$(OBJFILES)
	$(LD) $(LDFLAGS) -o amprd $(OBJFILES)

module:
	$(MAKE) -C ipip_redirector

all: module amprd

dist_clean: module_clean clean

clean:
	rm -f amprd *.o

module_clean:
	$(MAKE) -C ipip_redirector clean

install:	amprd
	install -m 755 -p -d -D                      $(SCACHEDIR)
	install -m 644 -p -b -D amprd.conf.example   $(CONFDIR)/amprd.conf.example
	install -m 755 -p -s -D amprd                $(SBINDIR)/amprd

uninstall:
	rm -fr $(SCACHEDIR)
	rm -f $(CONFDIR)/amprd.conf.example
	rm -f $(SBINDIR)/amprd

module_install:	module
	$(MAKE) -C ipip_redirector install

module_uninstall:	module
	$(MAKE) -C ipip_redirector uninstall
