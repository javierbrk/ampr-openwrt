/*
    file:   tunnel.c - part of ripd version 2.2

    Linux initial code: meoip.c - Denys Fedoryshchenko aka NuclearCat <nuclearcat (at) nuclearcat.com>
    FreeBSD support: Daniil Kharun <harunaga (at) harunaga.ru>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.*
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <poll.h>
#include <unistd.h>
#include <err.h>
#include <signal.h>

#include "tunnel.h"
#include "minIni.h"

#include "callhome.h"

#ifndef IPPORT_ROUTESERVER
#define IPPORT_ROUTESERVER 520
#endif


/*! Assert*/
#define assert(x, f) \
if  (x == NULL) \
  { warn("%s:%d %s: %m", __FILE__, __LINE__, f); exit(1);}

#define sizearray(a)  (sizeof(a) / sizeof((a)[0]))


int numtunnels;
Tunnel *tunnels;

int use_redirector;

void term_handler(int s)
{ 
  int 		fd, i;
  Tunnel	*tunnel;


  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket() failed");
    exit(-1);
  }

  for(i=0;i<numtunnels;i++)
  {
    tunnel = tunnels + i;

    close(tunnel->fd);

    if (tunnel->rip_fws >= 0)
    {
	close(tunnel->rip_fws);
    }
  }

  close(fd);
  exit(0);
}


int open_tun(Tunnel *tunnel)
{
    int fd;
    struct sockaddr_in sin;

    if ((fd = socket(PF_PACKET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
      perror("socket() failed");
      return 1;
    }

    if ( (tunnel->fd = open("/dev/net/tun",O_RDWR)) < 0)
    {
	perror("open_tun: /dev/net/tun error");
	return 1;
    }

    bzero(&tunnel->ifr, sizeof(tunnel->ifr));

    tunnel->ifr.ifr_flags = IFF_TAP|IFF_NO_PI;

    strncpy(tunnel->ifr.ifr_name, tunnel->name, IFNAMSIZ);


    if (ioctl(tunnel->fd, TUNSETIFF, (void *)&tunnel->ifr) < 0) {
        perror("ioctl-1");
        close(fd);
        return 1;
    }
    if (ioctl(tunnel->fd, TUNGETIFF, (void *)&tunnel->ifr) < 0) {
        perror("ioctlg-1");
        close(fd);
        return 1;
    }

    tunnel->ifr.ifr_flags |= IFF_UP;
    tunnel->ifr.ifr_flags |= IFF_RUNNING;
    tunnel->ifr.ifr_flags |= IFF_NOARP;

    if (ioctl(fd, SIOCSIFFLAGS, (void *)&tunnel->ifr) < 0) {
        perror("Set tunnel flags");
        close(fd);
        return 1;
    }

    tunnel->prefix.sin_family = AF_INET;
    memcpy(&tunnel->ifr.ifr_addr, &tunnel->prefix, sizeof(struct sockaddr));

    if (ioctl(fd, SIOCSIFADDR, (void *)&tunnel->ifr) < 0) {
        perror("Set tunnel address");
        close(fd);
        return 1;
    }

    tunnel->mask.sin_family = AF_INET;
    memcpy(&tunnel->ifr.ifr_addr, &tunnel->mask, sizeof(struct sockaddr));

    if (ioctl(fd, SIOCSIFNETMASK, (void *)&tunnel->ifr) < 0) {
        perror("Set tunnel mask");
        close(fd);
        return 1;
    }

    bzero(&tunnel->ifr, sizeof(tunnel->ifr));
    strncpy(tunnel->ifr.ifr_name, tunnel->name, IFNAMSIZ);

    if (ioctl(fd, SIOCGIFINDEX, (void *)&tunnel->ifr) < 0) {
        perror("Get tunnel index");
        close(fd);
        return 1;
    }

    tunnel->index = tunnel->ifr.ifr_ifindex;

    bzero(&tunnel->ifr, sizeof(tunnel->ifr));
    strncpy(tunnel->ifr.ifr_name, tunnel->name, IFNAMSIZ);

    if (ioctl(fd, SIOCGIFHWADDR,(void *)&tunnel->ifr) < 0) {
        perror("Get tunnel hardware address");
        close(fd);
        return 1;
    }

    memcpy(&tunnel->hwa, ((char *)&tunnel->ifr.ifr_hwaddr) + 2, ETH_ALEN);

    /* open RIP forward interface if needed */

    if (tunnel->rip_forward[0])
    {
	if ((tunnel->rip_fws = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0)
	{
	    perror("Forward socket");
	    close(fd);
	    return 1;
	}

	if (setsockopt(tunnel->rip_fws, SOL_SOCKET, SO_BINDTODEVICE, tunnel->rip_forward, strlen(tunnel->rip_forward)) < 0)
	{
	    perror("Forward socket: SO_BINDTODEVICE");
	    close(tunnel->rip_fws);
	    close(fd);
	    return 1;
	}

	memset((char *)&sin, 0, sizeof(sin));
	sin.sin_family = PF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(IPPORT_ROUTESERVER);

	if (bind(tunnel->rip_fws, (struct sockaddr *)&sin, sizeof(sin)))
	{
	    perror("Forward socket: bind");
	    close(tunnel->rip_fws);
	    close(fd);
	    return 1;
	}
    }

    close(fd);
    return 0;
}


int init_tun(char *config_file)
{
    int raw_socket;
    Tunnel *tunnel;
    int i, sn, plen;
    char section[IFNAMSIZ];
    char strbuf[256];
    char *p;

    struct sigaction sa;
    int do_home = FALSE;

    FILE *cf = fopen(config_file, "r");
    if (NULL == cf)
    {
    	fprintf(stderr, "Configuration file \"%s\" not found.\n", config_file);
    	exit(-1);
    }
    fclose(cf);

    for (sn = 0; ini_getsection(sn, section, sizearray(section), config_file) > 0; sn++)
    {
	numtunnels++;
    }

    if (0 == numtunnels)
    {
	fprintf(stderr, "No interfaces defined in configuration file.\n");
	exit(-1);
    }

    ini_gets("", "use_redirector", "", strbuf, sizeof(strbuf), config_file);
    if (0 == strcmp(strbuf, "yes"))
    {
	use_redirector = TRUE;
    }
    else
    {
	use_redirector = FALSE;
    }
    if (debug) fprintf(stderr, "Use redirector: %s\n", (use_redirector)?"yes":"no");

    tunnels = malloc(sizeof(Tunnel) * numtunnels);
    assert(tunnels, "malloc()");
    bzero(tunnels, sizeof(Tunnel) * numtunnels);

    for (sn = 0; ini_getsection(sn, section, sizearray(section), config_file) > 0; sn++)
    {
	tunnel = tunnels + sn;
	if (debug) fprintf(stderr, "Creating tunnel: %s\n", section);
	
	if (strlen(section) > IFNAMSIZ)
	{
	    fprintf(stderr, "Name of tunnel needs to be shotrer than %d symbols\n", IFNAMSIZ);
	    exit(-1);
	}
	strncpy(tunnel->name, section, IFNAMSIZ);
	
	if (ini_gets(section, "prefix", "", strbuf, sizeof(strbuf), config_file) < 1)
	{
	    fprintf(stderr, "Prefix for %s is not correct\n", section);
	    exit(-1);
	}
	else
	{
	    if (debug) fprintf(stderr, "Prefix for %s: %s\n", section, strbuf);
	}

	if ((p = strstr(strbuf, "/"))) *p = 0, p++;

	if (!inet_pton(AF_INET, strbuf, (struct in_addr *)&tunnel->prefix.sin_addr.s_addr))
	{
	    fprintf(stderr, "Address \"%s\" is not correct\n", strbuf);
	    exit(-1);
	}

	if ((p) && ((plen = strtol(p, NULL, 10)) > 32))
	{
	    fprintf(stderr, "Network prefix length \"/%s\" is not correct\n", strbuf);
	    exit(-1);
	}
	
	if (!p)
	{
	    if (debug) fprintf(stderr, "Network prefix length not set - assuming \"/8\"\n");
	    plen = 8;
	}
	
	for (i = 0; i < plen; i++)
	{
	    tunnel->mask.sin_addr.s_addr |= (htonl(0x80000000 >> i));
	}

	ini_gets(section, "multicast_in", "no", strbuf, sizeof(strbuf), config_file);
	if (0 == strcmp(strbuf, "yes"))
	{
	    tunnel->multicast_in = TRUE;
	}
	if (debug) fprintf(stderr, "Forward incoming multicast for %s: %s\n", section, (tunnel->multicast_in)?"yes":"no");

	ini_gets(section, "broadcast_in", "no", strbuf, sizeof(strbuf), config_file);
	if (0 == strcmp(strbuf, "yes"))
	{
	    tunnel->broadcast_in = TRUE;
	}
	if (debug) fprintf(stderr, "Forward incoming broadcast for %s: %s\n", section, (tunnel->broadcast_in)?"yes":"no");

	ini_gets(section, "default_via_ampr_gw", "yes", strbuf, sizeof(strbuf), config_file);
	if (0 == strcmp(strbuf, "yes"))
	{
	    tunnel->default_amprgw = TRUE;
	}
	if (debug) fprintf(stderr, "Use default ampr gateway for %s: %s\n", section, (tunnel->default_amprgw)?"yes":"no");

	ini_gets(section, "rip_receive", "yes", strbuf, sizeof(strbuf), config_file);
	if (0 == strcmp(strbuf, "yes"))
	{
	    tunnel->rip_recv = TRUE;
	}
	if (debug) fprintf(stderr, "Receiving RIPv2 for %s: %s\n", section, (tunnel->rip_recv)?"yes":"no");

	if (TRUE == tunnel->rip_recv)
	{
	
	    ini_gets(section, "rip_save", "no", strbuf, sizeof(strbuf), config_file);
	    if (0 == strcmp(strbuf, "yes"))
	    {
		tunnel->rip_save = TRUE;
	    }
	    if (debug) fprintf(stderr, "Saving routes for %s: %s\n", section, (tunnel->rip_save)?"yes":"no");

	    ini_gets(section, "rip_set_routes", "no", strbuf, sizeof(strbuf), config_file);
	    if (0 == strcmp(strbuf, "yes"))
	    {
		tunnel->rip_set = TRUE;
	    }
	    if (debug) fprintf(stderr, "Setting routes received by %s: %s\n", section, (tunnel->rip_set)?"yes":"no");
	
	    if (ini_gets(section, "rip_password", "", strbuf, sizeof(strbuf), config_file) > 0)
	    {
		if (strlen(strbuf) > 16)
		{
		    fprintf(stderr, "RIPv2 password for %s must be at most 16 symbols - not set\n", section);
		    tunnel->rip_passwd[0] = 0;
		}
		else
		{
		    strncpy(tunnel->rip_passwd, strbuf, 16);
		    if (debug) fprintf(stderr, "RIPv2 password for %s: %s\n", section, tunnel->rip_passwd);
		}
	    }
	    else
	    {
		strncpy(tunnel->rip_passwd, "pLaInTeXtpAsSwD", 16);;
	    }

	    if (ini_gets(section, "rip_ignore", "", strbuf, sizeof(strbuf), config_file) > 0)
	    {
		if (strlen(strbuf) > 256)
		{
		    fprintf(stderr, "RIPv2 gateway ignore list for %s must be shorter than 256 symbols - not set\n", section);
		    tunnel->rip_ignore[0] = 0;
		}
		else
		{
		    strncpy(tunnel->rip_ignore, strbuf, 256);
		    if (debug) fprintf(stderr, "RIPv2 gateway ignore list for %s: %s\n", section, tunnel->rip_ignore);
		}
	    }
	    else
	    {
		tunnel->rip_ignore[0] = 0;
	    }

	    if (ini_gets(section, "rip_forward", "", strbuf, sizeof(strbuf), config_file) > 0)
	    {
		if (strlen(strbuf) > IFNAMSIZ)
		{
		    fprintf(stderr, "RIPv2 forward interface name for %s must be shorter than %u symbols - not set\n", section, IFNAMSIZ);
		    tunnel->rip_forward[0] = 0;
		}
		else
		{
		    strncpy(tunnel->rip_forward, strbuf, IFNAMSIZ);
		    if (debug) fprintf(stderr, "RIPv2 gateway ignore list for %s: %s\n", section, tunnel->rip_forward);
		}
	    }
	    else
	    {
		tunnel->rip_forward[0] = 0;
	    }

	    if (ini_gets(section, "call_home", "", strbuf, sizeof(strbuf), config_file) > 0)
	    {
		if (strlen(strbuf) && strstr(strbuf, "@"))
		{
		    strncpy(tunnel->home_data, strbuf, MAXHOMEDATA);
		    if (debug) fprintf(stderr, "Call home set to %s\n", tunnel->home_data);
		}
		else
		{
		    if (debug) fprintf(stderr, "Invalid call home data\n");
		    tunnel->home_data[0] = 0;
		}
	    }
	    else
	    {
		tunnel->home_data[0] = 0;
	    }

	    tunnel->rip_fws = -1;
	}
	fprintf(stderr, "\n");
    }

    if (use_redirector)
    {
	raw_socket = socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT);
    }
    else
    {
	raw_socket = socket(PF_INET, SOCK_RAW, IPPROTO_IPIP);
    }

    if (raw_socket == -1)
    {
	perror("raw socket error():");
	exit(-1);
    }
    fcntl(raw_socket, F_SETFL, O_NONBLOCK);

    for(i=0; i<numtunnels; i++)
    {
	tunnel = tunnels + i;
	if (open_tun(tunnel))
	{
	    exit(-1);
	}
    }

    for(i=0; i<numtunnels; i++)
    {
	tunnel = tunnels + i;
	if (tunnel->home_data[0])
	{
	    callhome(tunnel, TRUE);
	    do_home = TRUE;
	}
    }

    if (do_home) alarm(30);

    bzero(&sa, sizeof(sa));
    sa.sa_handler = term_handler;
    sigaction(SIGTERM, &sa, 0);
    sigaction(SIGKILL, &sa, 0);
    sigaction(SIGINT, &sa, 0);

    return raw_socket;
}

