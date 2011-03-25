#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <fnmatch.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <math.h>

#define VERSION "0.1"

#include <linux/netdevice.h>
#include "libnetlink.h"

char **patterns;
int npatterns;

int match(char *id)
{
	int i;

	if (npatterns == 0)
		return 1;

	for (i=0; i<npatterns; i++) {
		if (!fnmatch(patterns[i], id, 0))
			return 1;
	}
	return 0;
}


static void usage(void) __attribute__((noreturn));

static void usage(void)
{
	fprintf(stderr,
"Usage: estat [ -h?vV ] [ PATTERN [ PATTERN ] ]\n"
		);
	exit(-1);
}


void format_rate(FILE *fp, unsigned long i)
{
        if (i > 1024*1024*1024)
                fprintf(fp, "%3lu M", i/(1024*1024));
        else if (i > 1024*1024)
                fprintf(fp, "%3lu k", i/1024);
        else
                fprintf(fp, "%4lu ",  i);

	fprintf(fp, "pps ");
}

void format_bits(FILE *fp, unsigned long i)
{
	double d = i;

        if (d > 128*1024)
                fprintf(fp, "%3.1f M", d/(128*1024));

        else if (d > 128)
                fprintf(fp, "%3.1f k", d/128);
        else
                fprintf(fp, "%4.1f  ",  d*8);

	fprintf(fp, "bit/s ");
}


void print_one_if(FILE *fp)
{
  char buf[4096];
  char *p;
  char if_name [40];
  unsigned long 
    rx_bytes, 
    rx_packets, 
    rx_errors,
    rx_dropped,
    rx_fifo_errors,
    rx_crc_errors,
    rx_compressed, 
    multicast,
    tx_bytes,
    tx_packets, 
    tx_errors, 
    tx_dropped,
    tx_fifo_errors, 
    collisions,
    tx_carrier_errors,
    tx_compressed;

		
  fgets(buf, sizeof(buf), fp);
  fgets(buf, sizeof(buf), fp);
  fgets(buf, sizeof(buf), fp);
  fgets(buf, sizeof(buf), fp);

  fgets(buf, sizeof(buf), fp);
  fgets(buf, sizeof(buf), fp);
  fgets(buf, sizeof(buf), fp);
  fgets(buf, sizeof(buf), fp);
  fgets(buf, sizeof(buf), fp); /* Last line holds ave stats */

  p = strchr(buf, ':');
  if(p) *p = ' ';
  sscanf (buf, 
	  "%s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
	  if_name,
	  &rx_bytes,
	  &rx_packets, 
	  &rx_errors,
	  &rx_dropped,
	  &rx_fifo_errors,
	  &rx_crc_errors,
	  &rx_compressed, 
	  &multicast,
	  &tx_bytes,
	  &tx_packets, 
	  &tx_errors, 
	  &tx_dropped,
	  &tx_fifo_errors, 
	  &collisions,
	  &tx_carrier_errors,
	  &tx_compressed);

  fprintf(stdout, "%s: ", if_name);
  format_bits(stdout, rx_bytes);
  format_rate(stdout, rx_packets);
  format_bits(stdout, tx_bytes);
  format_rate(stdout, tx_packets);

  fprintf(stdout, "%s", "\n");

#if 0
  fprintf (stdout, 
	   "%s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
	   if_name,
	   rx_bytes,
	   rx_packets, 
	   rx_errors,
	   rx_dropped,
	   rx_fifo_errors,
	   rx_crc_errors,
	   rx_compressed, 
	   multicast,
	   tx_bytes,
	   tx_packets, 
	   tx_errors, 
	   tx_dropped,
	   tx_fifo_errors, 
	   collisions,
	   tx_carrier_errors,
	   tx_compressed);
#endif

}

void print_if(char *dev)
{
	FILE *fp = NULL;
	char tmp[120];

	sprintf(tmp, "/proc/net/stats/%s", dev);

	if ((fp = fopen(tmp, "r")) != NULL) {
	  
	  print_one_if(fp);
	  fclose(fp);
	}
	else {
		fprintf(stderr, "%s ", tmp);
		perror("open");
		abort();
	}
}

int get_nlmsg(struct sockaddr_nl *who, struct nlmsghdr *m, void *arg)
{
        struct ifinfomsg *ifi = NLMSG_DATA(m);
        struct rtattr * tb[IFLA_MAX+1];
	char *if_name;
        int len = m->nlmsg_len;

        if (m->nlmsg_type != RTM_NEWLINK)
                return 0;

        len -= NLMSG_LENGTH(sizeof(*ifi));
        if (len < 0)
                return -1;

        if (!(ifi->ifi_flags&IFF_UP))
                return 0;

        memset(tb, 0, sizeof(tb));
        parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);
        if (tb[IFLA_IFNAME] == NULL || tb[IFLA_STATS] == NULL)
                return 0;

	if(match(RTA_DATA(tb[IFLA_IFNAME]))) {
		if_name = strdup(RTA_DATA(tb[IFLA_IFNAME]));
		print_if(if_name);	
	}
	return 1;
}

int main(int argc, char *argv[])
{
	int ch;
	struct rtnl_handle rth;
 

	while ((ch = getopt(argc, argv, "h?vV")) != EOF) {
		switch(ch) {

		case 'v':
		case 'V':
			printf("estat utility %s \n", VERSION);
			exit(0);
		case 'h':
		case '?':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	patterns = argv;
	npatterns = argc;


	if (rtnl_open(&rth, 0) < 0)
                exit(1);

        if (rtnl_wilddump_request(&rth, AF_INET, RTM_GETLINK) < 0) {
                perror("Cannot send dump request");
                exit(1);
        }

        if (rtnl_dump_filter(&rth, get_nlmsg, NULL, NULL, NULL) < 0) {
                fprintf(stderr, "Dump terminated\n");
                exit(1);
        }

        rtnl_close(&rth);

	exit(0);
}


