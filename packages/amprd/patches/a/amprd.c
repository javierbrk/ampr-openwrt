/*
 * amprd.c - AMPR 44net Interface daemon version 2.2
 *
 * Author: Marius Petrescu, YO2LOJ, <marius@yo2loj.ro>
 *
 ****************************************
 * To my son Marcel Petrescu (2005-2017)
 ****************************************
 *
 * Usage: ampr-ripd [-?|-h] [-d] [-v] [-c <configuration_file>] [-p <pid_file>]
 *
 * Options:
 *          -?, -h                Usage info
 *          -d                    Debug mode: no daemonization, verbose output
 *          -v                    More verbose debug output
 *          -c config_file        Allows you to specify another configuration file.
 *                                The default one is /etc/amprd.conf
 *          -p pid_file	          Allows to specify a PID file
 *                                Default is no PID file
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *
 * Version History
 * ---------------
 *    1.0     6.Aug.2013    First version
 *    1.1     8.Aug.2013    Bug fix: routes were set even if set to disabled in config
 *                          Bug fix: accepted routes with distance 15
 *                          Bug fix: RIP entries were processed past end of packet
 *    1.2     9.Aug.2013    Bug fix: Buffer overflow on ipip read (tnx. Don Fanning).
 #    1.3    10.Aug.2013    Bug fix: Corrected a stupid error in netmask calculation
 *    1.4    10.Aug.2013    Bug fix: Corrected a bug in netmask host/network translation
 *    1.5     3.Apr.2017    Added support for PID file
 *                          Added support for BGP announced 44net endpoints
 *    1.6     8.Apr.2017    Bug fix: Corrected host routes not being set when rip_set_routes = no
 *                          Password is hardcoded, only needs to be set if changed
 *    2.0     2.Jun.2017    Update default AMPR gateway to the new IP
 *                          Added call home functionality
 *    2.1     4.Jun.2017    Force call home to use interface IP as source
 *                          Support for call home on multiple interfaces
 *    3.0     5.Jun.2017    Added support for AMPR subnetst in ignore list (for dynamic IP endpoints)
 *                          Added enable/disable forward of incoming multicast and broadcast data
 *                          Added support for selectable PID file
 *                          Added support for IPIP redirector kernel module
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#include "tunnel.h"
#include "list.h"
#include "rip.h"
#include "encap.h"
#include "cache.h"
#include "route.h"
#include "callhome.h"
#include "commons.h"

#define MAXPAYLOAD 		(2048)

char *passwd = NULL;
int debug = FALSE;
int verbose = FALSE;

char *conf_file = CONF_FILE;

char *pid_file = NULL;

char *usage_string = "\nAmpr daemon v2.2 by Marius, YO2LOJ\n\nUsage: amprd [-d] [-v] [-c <configuration_file>]\n";

int *updated;

int route_event = FALSE;

uint32_t general_ampr_gw;

uint32_t myips[MYIPSIZE];


void (*sigterm_defhnd)(int);


void on_alarm(int sig)
{

    int i;
    int count;

    route_entry *p;
    Tunnel *tunnel;

    int do_home = FALSE;

    if (debug)
    {
        if (verbose) fprintf(stderr, "SIGALRM received.\n");
	if (route_event) fprintf(stderr, "Checking for expired routes.\n");
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

    if (FALSE == route_event)
    {
	return;
    }

    for(i=0; i<numtunnels; i++)
    {
	tunnel = tunnels + i;
	
	if (FALSE == tunnel->rip_recv)
	    continue;
	
	/* check route expiration */
	count = 0;
	p = list_head(i);

	while (p->next)
	{
	    if ((p->next->timestamp + ROUTE_EXPIRE_TIME) < time(NULL))
	    {
		list_remove(p->next);
		count++;
		updated[i] = TRUE;
	    } 
	    else
	    {
		p = p->next;
	    }
	}

	if (debug) fprintf(stderr, "%d expired routes for tunnel %s.\n", count, tunnel->name);

	/* save if needed */
	if ((TRUE == tunnel->rip_save) && (TRUE == updated[i]) && (TRUE == tunnel->rip_recv))
	{
	    if (debug) fprintf(stderr, "Saving %d entries to file %s.txt.\n", list_count(i), tunnel->name);
	    save_encap(i);
	    updated[i] = FALSE;
	}
	else
	{
	    if (debug && verbose) fprintf(stderr, "Saving to disk not needed for %s.\n", tunnel->name);
	}
    }

    route_event = FALSE;
}

void on_hup(int sig)
{
    debug = FALSE;
    verbose = FALSE;
}

void on_term(int sig)
{
    int i;
    Tunnel *tunnel;

    for(i=0; i<numtunnels; i++)
    {
	tunnel = tunnels + i;

	if (tunnel->home_data[0])
	{
	    callhome(tunnel, FALSE);
	}
    }

    signal(SIGTERM, SIG_IGN);

    route_clear_all();

    remove(pid_file);

    signal(SIGTERM, sigterm_defhnd);
    raise(SIGTERM);
}

int32_t ns_resolv(const char *name)
{
    struct hostent *host;

    host = gethostbyname(name);

    if (host == NULL) return 0;
    if (host->h_addrtype != AF_INET) return 0;

    return ((struct in_addr) *((struct in_addr *) host->h_addr_list[0])).s_addr;
}

uint32_t getip(const char *dev)
{
    struct ifreq ifr;
    int res;

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return 0;

    memset(&ifr, 0, sizeof(struct ifreq));
    strcpy(ifr.ifr_name, dev);
    res = ioctl(sockfd, SIOCGIFADDR, &ifr);
    close(sockfd);
    if (res < 0) return 0;
    return ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
}

void detect_myips(void)
{
    int i, j;
    uint32_t ipaddr;

    struct in_addr ad;

    struct if_nameindex *names;

    for (i=0; i<MYIPSIZE; i++) myips[i] = 0;

    names = if_nameindex();

    if (NULL == names)
    {
	return;
    }

    i = 0;
    while ((names[i].if_index != 0) && (names[i].if_name != NULL) && (i<MYIPSIZE))
    {
	ipaddr = getip(names[i].if_name);

	if (debug && verbose)
	{
	    ad.s_addr = ipaddr;
	    fprintf(stderr, "Interface detected: %s, IP: %s\n", names[i].if_name, inet_ntoa(ad));
	}

	/* check if address not already there */
	for (j=0; j<MYIPSIZE; j++)
	{
	    if ((myips[j] == ipaddr) || (0 == myips[j])) break;
	}
	if (MYIPSIZE != j) myips[j] = ipaddr;

	i++;
    }

    if_freenameindex(names);

    if (debug && verbose)
    {
	fprintf(stderr, "Local IPs:\n");
        for (i=0; i<MYIPSIZE; i++)
	{
	    if (0 == myips[i]) break;
	
	    ad.s_addr = myips[i];
	    fprintf(stderr, "   %s\n", inet_ntoa(ad));
	}
    }
}

int check_ignore(uint16_t tunid, uint32_t ip, unsigned int netmask)
{
	char ipstr[20];
	char *sptr;
	char *ptr;
	int i;
	struct in_addr ipa;

	Tunnel *tunnel = tunnels + tunid;

	/* check for a local interface match */
	for (i=0; i<MYIPSIZE; i++)
	{
	    if (0 == myips[i]) break;
	    if (ip == myips[i]) return TRUE;
	}

	/* check for a match in the ignore list */
	ipa.s_addr = ip;
	sprintf(ipstr,"%s", inet_ntoa(ipa));
	sptr = tunnel->rip_ignore;

	if (netmask)
	{
	    sprintf(ipstr + strlen(ipstr), "/%2d", netmask);
	}

	while ((ptr = strstr(sptr, ipstr)) != NULL)
	{
	    /* we have ip as substring in the list - have to check if it is the complete ip - has to have a comma or 0 after it */
	    if ((ptr[strlen(ipstr)] == ',')||(ptr[strlen(ipstr)] == 0))
	    {
		/* ip is in ignore list */
		return TRUE;
	    }
	    /* false alarm, continue search */
	    sptr = &ptr[strlen(ipstr)];
	}

	/* the ip is valid */
	return FALSE;
};


int main(int argc, char**argv)
{
    int raw_socket;
    struct pollfd *pollfd;
    int i, j, payload, best, mask, bmask;
    Tunnel *tunnel;
    FILE *pidfile;

    char *ip = malloc(MAXPAYLOAD + 18);   /* eth header + tcp/ip frame + checksum */
    char *rcv = malloc(MAXPAYLOAD + 20);  /* ip header + tcp/ip frame */
    struct iphdr *chdr = (struct iphdr *)(rcv + 20);
    struct udphdr *uhdr = (struct udphdr *)(rcv + 40);
    struct ethhdr *eh = (struct ethhdr *)(rcv + 6);

    struct iphdr *iph = (struct iphdr *)(ip + 14);
    struct ethhdr *ih = (struct ethhdr *)(ip);

    struct sockaddr_in daddr;

    struct sigaction sa;

    int p;

    while ((p = getopt(argc, argv, "dvh?:c:p:")) != -1)
    {
	switch (p)
	{
	    case 'd':
		debug = TRUE;
		break;
	    case 'v':
		verbose = TRUE;
		break;
	    case 'c':
		conf_file = optarg;
		break;
	    case 'p':
		pid_file = optarg;
		break;
	    case 'h':
	    case '?':
	    case ':':
		fprintf(stderr, "%s", usage_string);
		exit (-1);
	}
    }

    general_ampr_gw =  GENERAL_AMPR_GW;

    defgw = route_func(0, ROUTE_GET, inet_addr("8.8.8.8"), 32, 0);
    gwdev = route_func(0, ROUTE_GETDEV, defgw, 32, 0);

    if (debug) 
    {
	struct in_addr addr;
	addr.s_addr = defgw;
	printf("Default gateway: %s via dev %d.\n", inet_ntoa(addr), gwdev);
    }

    raw_socket = init_tun(conf_file);
    list_init();
    cache_init();
    detect_myips();

    updated = malloc(sizeof(int) * numtunnels);
    bzero(updated, sizeof(int) * numtunnels);

    for (i=0; i<numtunnels; i++)
    {
	tunnel = tunnels + i;

	mask = 1;
	bmask = 0;
	for(j=0; j<32; j++)
	{
	    if (mask & tunnel->mask.sin_addr.s_addr)
	    {
		bmask++;
	    }
	    mask <<= 1;
	}

	if (TRUE == tunnel->rip_recv) load_encap(i);
    }

    /* hard coded default gateways */
    for(i=0; i<numtunnels; i++)
    {
	if (NULL == list_find(i, inet_addr("44.0.0.1"), 32))
	{
	    list_update(i, inet_addr("44.0.0.1"), 32, general_ampr_gw);
	}
    }

    route_set_all();

    bzero(&sa, sizeof(sa));
    sa.sa_handler = on_alarm;
    sigaction(SIGALRM, &sa, 0);
    sa.sa_handler = on_hup;
    sigaction(SIGHUP, &sa, 0);

    if (FALSE == debug)
    {
	pid_t fork_res = -1;
	fork_res = fork();

	if (-1 == fork_res)
	{
	    fprintf(stderr, "Can not become a daemon.\n");
	    exit(1);
	}

	if (0 != fork_res)
	{
	    /* exit parent */
	    exit(0);
	}
    }

    sa.sa_handler = on_term;
    sigaction(SIGTERM, &sa, 0);
    if (pid_file)
    {
	pidfile = fopen(pid_file, "w");
	if (pidfile == NULL)
	{
	    fprintf(stderr, "Warning: Can not create PID file %s\n", pid_file);
	}
	else
	{
	    fprintf(pidfile, "%d\n", (int)getpid());
	    fclose(pidfile);
	}
    }

    pollfd = malloc(sizeof(struct pollfd) * (numtunnels + 1));

    pollfd[0].fd = raw_socket;
    pollfd[0].events = POLLIN;
    pollfd[0].revents = 0;

    for(i=0; i<numtunnels; i++)
    {
	tunnel = tunnels + i;
	fcntl(tunnel->fd, F_SETFL, O_NONBLOCK);
	pollfd[i + 1].fd = tunnel->fd;
	pollfd[i + 1].events = POLLIN;
	pollfd[i + 1].revents = 0;
    }

    while(1) {

	while (poll(pollfd, numtunnels + 1, -1) >= 0)
	{
	    if (pollfd[0].revents)
	    {

		if ((payload = read(raw_socket, rcv, MAXPAYLOAD + 20)) < 20) /* ip header + tcp/ip frame */
		    continue;

		/* find best tunnel */
		bmask = 0;
		best = 0;
		for (i=0; i<numtunnels; i++)
		{
		    tunnel = tunnels + i;
		
		    /* unicast to tunnel IP */
		    if (tunnel->prefix.sin_addr.s_addr == chdr->daddr) 
		    {
			bmask = 0xffffffff;
			best = i;
			break;
		    }
		
		    /* first tunnel with biggest mask */
		    if ((tunnel->prefix.sin_addr.s_addr & tunnel->mask.sin_addr.s_addr) == (chdr->daddr & tunnel->mask.sin_addr.s_addr)) 
		    {
			if (bmask < tunnel->mask.sin_addr.s_addr)
			{
			    bmask = tunnel->mask.sin_addr.s_addr;
			    best = i;
			}
		    }
		}
		
		if (bmask != 0) /* we found the target tunnel with biggest netmask */
		{
		    tunnel = tunnels + best;
		    if (debug & verbose) printf("IPIP incoming - selected best tunnel: %s (%d).\n", tunnel->name, best);
		    bzero(eh, 14);
		    eh->h_proto = htons(ETH_P_IP);
		    memcpy(&eh->h_dest, &tunnel->hwa, ETH_ALEN);
		    memcpy(&eh->h_source, &tunnel->hwa, ETH_ALEN);
		    write(tunnel->fd, eh, payload - 6); /* remainder of ip header */
		}
		else /* multicasts and broadcasts go to multipe targets as configured */
		{
		    for (i=0; i<numtunnels; i++)
		    {
			tunnel = tunnels + i;
		
			if (
			    ((tunnel->multicast_in) && ((chdr->daddr & inet_addr("224.0.0.0")) == inet_addr("224.0.0.0"))) ||                    /* multicast */
			    ((tunnel->broadcast_in) &&
			     (
			      ((tunnel->prefix.sin_addr.s_addr & tunnel->mask.sin_addr.s_addr) == chdr->daddr) ||                                /* network */
			      ((tunnel->prefix.sin_addr.s_addr |  ~tunnel->mask.sin_addr.s_addr) == chdr->daddr) ||                              /* broadcast */
			      (chdr->daddr == inet_addr("255.255.255.255"))                                                                      /* anycast */
			     )
			    )
			   )
			{
			    bzero(eh, ETH_HLEN);
			    eh->h_proto = htons(ETH_P_IP);
			    memcpy(&eh->h_dest, &tunnel->hwa, ETH_ALEN);
			    memcpy(&eh->h_source, &tunnel->hwa, ETH_ALEN);
			    write(tunnel->fd, eh , payload - 6);
			}
		    }
		}

		if (
		    (payload > 48) &&
		    ((chdr->daddr == inet_addr("224.0.0.9")) && (chdr->saddr == inet_addr("44.0.0.1"))) &&  /* multicasts from 44.0.0.1 */
		    (uhdr->source == htons(IPPORT_ROUTESERVER) &&  uhdr->dest == htons(IPPORT_ROUTESERVER)) /* port 520 (RIP) */
	        )
		{
		    if (debug) fprintf(stderr, "Ampr GW multicast RIPv2 received: %d bytes\n", payload - 48);
		    rip_process_message(rcv + 48, payload - 48);
		}
	
		continue;
	    }
	

	    for (i=0; i< numtunnels; i++)
	    {
		tunnel = tunnels + i;
	
		if (pollfd[i + 1].revents)
		{
		    pollfd[i + 1].revents = 0;
		
		    payload = read(tunnel->fd, ip, MAXPAYLOAD + 18); /* eth header + tcp/ip frame + checksum */
		
		    if (payload < 34)
			break;
		
		    if (ih->h_proto != htons(ETH_P_IP))
			break;
		
		    if (
			((iph->daddr & inet_addr("224.0.0.0")) == inet_addr("224.0.0.0")) ||  /* multicast */
			(iph->daddr == inet_addr("44.0.0.0")) ||                              /* network */
			(iph->daddr == inet_addr("44.255.255.255")) ||                        /* broadcast */
			(iph->daddr == inet_addr("255.255.255.255"))                          /* anycast */
			)
		    {
			/* Forwarding these is a huge task - they should go to every gateway in our routing table */
			/* Better drop them for the moment since basically noone is using them. This could be added in the future */
			if (debug && verbose) fprintf(stderr, "Dropping broadcast/multicast to %s.\n", inet_ntoa(*(struct in_addr *)&iph->daddr));
			break;
		    }
		
		    if (debug && verbose)
		    {
			fprintf(stderr, "Outgoing IP Frame: %d bytes\n", payload - 14);
			fprintf(stderr, "Looking for route to %s ...\n", inet_ntoa(*(struct in_addr *)&iph->daddr));
		    }
		
		    /* find the gateway */
		    bzero(&daddr, sizeof(daddr));
		    daddr.sin_family = AF_INET;
		    daddr.sin_port = 0;
		    daddr.sin_addr.s_addr = cache_lookup(i, iph->daddr);
		
		    if (daddr.sin_addr.s_addr) /* tunnel endpoint available */
		    {
			if (debug && verbose)
			{
			    fprintf(stderr, "Packet to %s ", inet_ntoa(*(struct in_addr *)&iph->daddr));
			    fprintf(stderr ,"via %s\n", inet_ntoa(*(struct in_addr *)&daddr.sin_addr));
			}
			if (sendto(raw_socket, ip + 14, payload - 14, 0, (struct sockaddr *)&daddr, (socklen_t)sizeof(daddr)) < 0)
			    perror("encap send() err");
		    }
		    else /* anything else goes unencapsulated via system routes */
		    {
			if (debug && verbose)
			{
			    fprintf(stderr, "Drop packet to %s - no gateway\n", inet_ntoa(*(struct in_addr *)&iph->daddr));
			}
		    }
		    break;
		}
	    }
	}
    }
    exit(0);	/* we never reach this */
}
