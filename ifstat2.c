/*
 * ifstat.c	handy utility to read net interface statistics
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 * Reduced and rewritten for mortals and forked to ifstat2
 *              Robert Olsson <robert.olsson@its.uu.se>
 * Further usability fixes: Jens Låås <jens.laas@its.uu.se>
 *
 */

#define VERSION "0.33"

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
#include <poll.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <math.h>
#include <sys/types.h>

#include "stats64.h"
#include "libnetlink.h"
#include <linux/netdevice.h>

struct {
	int scan_interval;
	int min_interval;
	int time_constant;
	int show_errors;
	int noformat;
	int verbose;
	int foreground;
} conf;

double W;
char **patterns;
int npatterns;

char info_source[128];

/* Keep in sync */


#define DEFAULT_INTERVAL 1
#define DEFAULT_TIME_CONST 5


#define MAXS (sizeof(struct ifstats64)/sizeof(uint64_t))

struct ifstat_ent
{
	struct ifstat_ent	*next;
	char			*name;
	int			ifindex;
	uint64_t                val[MAXS];
	double			rate[MAXS];
};


struct ifstat_ent *kern_db;

int ewma;
int overflow;

static int match(char *id)
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

static int get_netstat_nlmsg(struct sockaddr_nl *who, struct nlmsghdr *m, void *arg)
{
	struct ifinfomsg *ifi = NLMSG_DATA(m);
	struct rtattr * tb[IFLA_MAX+1];
	int len = m->nlmsg_len;
	struct ifstat_ent *n;
	uint64_t ival[MAXS];
	int i;

	if (m->nlmsg_type != RTM_NEWLINK)
		return 0;

	len -= NLMSG_LENGTH(sizeof(*ifi));
	if (len < 0)
		return -1;

	if (!(ifi->ifi_flags&IFF_UP))
		return 0;

	memset(tb, 0, sizeof(tb));
	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);
	if (tb[IFLA_IFNAME] == NULL || tb[IFLA_STATS64] == NULL)
		return 0;

	n = malloc(sizeof(*n));
	if (!n)
		abort();
	n->ifindex = ifi->ifi_index;
	n->name = strdup(RTA_DATA(tb[IFLA_IFNAME]));
	memcpy(&ival, RTA_DATA(tb[IFLA_STATS64]), sizeof(ival));
	for (i=0; i<MAXS; i++) {

#undef DO_L2_STATS
#ifdef DO_L2_STATS

		if(i == 2) n->ival[i] = n->ival[i]+4; /* RX CRC */
		if(i == 3) n->ival[i] = n->ival[i]+18; /* TX 14+4 E-hdr + CRC */
#endif
		n->val[i] = ival[i];
	}
	n->next = kern_db;
	kern_db = n;
	return 0;
}


static void load_info(void)
{
	struct ifstat_ent *db, *n;
	struct rtnl_handle rth;

	if (rtnl_open(&rth, 0) < 0)
		exit(1);

	if (rtnl_wilddump_request(&rth, AF_INET, RTM_GETLINK) < 0) {
		perror("Cannot send dump request");
		exit(1);
	}

	if (rtnl_dump_filter(&rth, get_netstat_nlmsg, NULL, NULL, NULL) < 0) {
		fprintf(stderr, "Dump terminated\n");
		exit(1);
	}

	rtnl_close(&rth);

	db = kern_db;
	kern_db = NULL;

	while (db) {
		n = db;
		db = db->next;
		n->next = kern_db;
		kern_db = n;
	}
}


/* 
   Read data from unix socket 
*/

static void load_raw_table(FILE *fp)
{
	char buf[4096];
	struct ifstat_ent *db = NULL;
	struct ifstat_ent *n;

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		char *p;
		char *next;
		int i;

		if (buf[0] == '#') {
			buf[strlen(buf)-1] = 0;
			strncpy(info_source, buf+1, sizeof(info_source)-1);
			continue;
		}
		if ((n = malloc(sizeof(*n))) == NULL)
			abort();

		if (!(p = strchr(buf, ' ')))
			abort();
		*p++ = 0;

		if (sscanf(buf, "%d", &n->ifindex) != 1)
			abort();
		if (!(next = strchr(p, ' ')))
			abort();
		*next++ = 0;

		n->name = strdup(p);
		p = next;

		for (i=0; i<MAXS; i++) {
			unsigned rate;
			if (!(next = strchr(p, ' ')))
				abort();
			*next++ = 0;
			if (sscanf(p, "%llu", n->val+i) != 1)
				abort();

			p = next;
			if (!(next = strchr(p, ' ')))
				abort();
			*next++ = 0;
			if (sscanf(p, "%u", &rate) != 1)
				abort();
			n->rate[i] = rate;
			p = next;
		}
		n->next = db;
		db = n;
	}

	while (db) {
		n = db;
		db = db->next;
		n->next = kern_db;
		kern_db = n;
	}
}

/* 
   Write data to socket 
*/

static void dump_raw_db(FILE *fp)
{
	struct ifstat_ent *n;

	fprintf(fp, "#ovrf=%d EWMA=%d client-pid=%u -- %s\n", 
		overflow, ewma, getpid(), info_source);

	for (n=kern_db; n; n=n->next) {
		int i;

		fprintf(fp, "%d %s ", n->ifindex, n->name);
		for (i=0; i<MAXS; i++) {
			fprintf(fp, "%llu %u ", n->val[i], (unsigned)n->rate[i]);
		}
		fprintf(fp, "\n");
	}
}

static void format_rate(FILE *fp, struct ifstat_ent *n, int i)
{
	char temp[64];
#if 0
	if (n->val[i] > 1024*1024*1024)
		fprintf(fp, "%7lluM ", n->val[i]/(1024*1024));
	else if (n->val[i] > 1024*1024)
		fprintf(fp, "%7lluK ", n->val[i]/1024);
	else
		fprintf(fp, "%8llu ", n->val[i]);

#endif
	if (n->rate[i] > 1024*1024) {
		sprintf(temp, "%uM", (unsigned)(n->rate[i]/(1024*1024)));
		fprintf(fp, "%-11s ", temp);
	} else if (n->rate[i] > 1024) {
		sprintf(temp, "%uK", (unsigned)(n->rate[i]/1024));
		fprintf(fp, "%-11s ", temp);
	} else
		fprintf(fp, "%-11u ", (unsigned)n->rate[i]);
}

static void print_head(FILE *fp)
{
	if(conf.noformat) {
		return;
	}
	
	if(conf.verbose) fprintf(fp, "#%s\n", info_source);
	if(!conf.show_errors) {
		fprintf(fp, "%42s", "RX --------------------------");	
		fprintf(fp, "%-30s\n", "   TX --------------------------");
		return;
	}

	fprintf(fp, "%-10s ", "Interface");

	fprintf(fp, "%12s", "RX Pkts" );
	fprintf(fp, "%12s", "TX Pkts" );
	fprintf(fp, "%12s", "RX Data" );
	fprintf(fp, "%12s\n","TX Data" );

	fprintf(fp, "%-10s ", "");
	fprintf(fp, "%12s", "RX Errs");
	fprintf(fp, "%12s", "RX Drop");
	fprintf(fp, "%12s", "RX Over");
	fprintf(fp, "%12s\n","RX Leng");

	fprintf(fp, "%-10s ", "");
	fprintf(fp, "%12s", "RX Crc ");
	fprintf(fp, "%12s", "RX Frm ");
	fprintf(fp, "%12s", "RX Fifo");
	fprintf(fp, "%12s\n","RX Miss");
	
	fprintf(fp, "%-10s ", "");
	fprintf(fp, "%12s", "TX Errs");
	fprintf(fp, "%12s", "TX Drop");
	fprintf(fp, "%12s", "Colli  ");
	fprintf(fp, "%12s\n","TX Carr");

	fprintf(fp, "%-10s ", "");
	fprintf(fp, "%12s", "TX Abrt");
	fprintf(fp, "%12s", "TX Fifo");
	fprintf(fp, "%12s", "TX Hbt ");
	fprintf(fp, "%12s\n","TX Wind");
}

static void nformat_rate(FILE *fp, double x)
{
	char temp[64];
	uint64_t i = x;
	
	if(conf.noformat) {
		fprintf(fp, "%llu pps ", i);
		return;
	}

	if (i > 1500*1000)
		sprintf(temp, "%5.3f M",
			((double)(i/1000))/1000);
	else if (i > 5*1000)
		sprintf(temp, "%7llu k", i/(1000));
	else
		sprintf(temp, "%7llu  ", i);
	
	fprintf(fp, "%10s %s", temp, "pps ");
}

static void nformat_bits(FILE *fp, double d)
{
	char temp[64];

	if(conf.noformat) {
		fprintf(fp, "%.0f bits/s ", d*8);
		return;
	}

	/*
	  IEC standard 1998
	  kbit = 1000 bits
	  Mbit = 10^6 bits
	  Gbit = 10^9 bits
	*/

        if (d >= 125*1000*1000) 
		sprintf(temp, "%3.1f G", d/((1000/8)*1000*1000));
        else if (d >= 125*1000) 
		sprintf(temp, "%3.1f M", d/((1000/8)*1000));
        else if (d >= 128) 
		sprintf(temp, "%3.1f k", d/(1000/8));
        else 
		sprintf(temp, "%4.0f  ", d*8);

	fprintf(fp, "%10s %s", temp, "bit/s ");
}


static void print_one_if(FILE *fp, struct ifstat_ent *n)
{
	int i;

	if(!conf.show_errors) {

		if(conf.noformat)
			fprintf(fp, "%s ", n->name);
		else
			fprintf(fp, "%-10s ", n->name);
		nformat_bits(fp, n->rate[2]);
		nformat_rate(fp, n->rate[0]);
		nformat_bits(fp, n->rate[3]);
		nformat_rate(fp, n->rate[1]);
		
		fprintf(fp, "%s", "\n");
		
		return;
	}  


	fprintf(fp, "%-15s ", n->name);
	for (i=0; i<4; i++)
		format_rate(fp, n, i);
	fprintf(fp, "\n");

	fprintf(fp, "%-15s ", "");
	format_rate(fp, n, 4); /* rx_err */
	format_rate(fp, n, 6); /* rx_dropped */
	format_rate(fp, n, 11);/* rx_over_err */
	format_rate(fp, n, 10); /* rx_len_err */
	fprintf(fp, "\n");

	fprintf(fp, "%-15s ", "");
	format_rate(fp, n, 12); /* rx_crc_err */
	format_rate(fp, n, 13); /* rx_frame_err */
	format_rate(fp, n, 14); /* rx_fifo_err */
	format_rate(fp, n, 15); /* rx_missed_err */
	fprintf(fp, "\n");
	
	fprintf(fp, "%-15s ", "");
	format_rate(fp, n, 5); /* tx_err */
	format_rate(fp, n, 7); /* tx_dropped */
	format_rate(fp, n, 9); /* collisons */
	format_rate(fp, n, 17); 
	fprintf(fp, "\n");
	
	fprintf(fp, "%-15s ", "");
	format_rate(fp, n, 16);
	format_rate(fp, n, 18);
	format_rate(fp, n, 19);
	format_rate(fp, n, 20);
	fprintf(fp, "\n");
}


static void dump_kern_db(FILE *fp)
{
	struct ifstat_ent *n;


	print_head(fp);

	for (n=kern_db; n; n=n->next) {
		if (!match(n->name))
			continue;
		print_one_if(fp, n);
	}
}

static int children;

void sigchild(int signo)
{
}

static void update_db(int interval)
{
	struct ifstat_ent *n, *is_new, *ns;

	
	n = kern_db;
	kern_db = NULL;

	load_info();

	is_new = kern_db; 
	kern_db = n;

	/* 
	   Update current as template to detect any
	   new or removed devs.
	*/
	for (ns = is_new; ns; ns = ns->next) {

		if(!conf.scan_interval) 
			abort();

		for (n = kern_db; n; n = n->next) {
			if (ns->ifindex == n->ifindex) {
				int i;

				for (i = 0; i < MAXS; i++) { 
					uint64_t diff;
					double sample;
					
					/* Handle one overflow correctly */

					if( ns->val[i] < n->val[i] ) {
						diff = (0xFFFFFFFF - n->val[i]) + ns->val[i]; 
						overflow++;
					}
					else 
						diff = ns->val[i] - n->val[i];

//					ns->ival[i] = n->ival[i]; /* For overflow check */
//					ns->val[i]  = n->val[i];

					if(interval <= conf.min_interval) {
						ewma = -11;
						ns->rate[i] = n->rate[i];
						goto done;
					}
					
					/* Calc rate */
					
					sample = (double)(diff*1000)/interval;

                                        if (interval >= conf.scan_interval) {
                                                ns->rate[i] =  n->rate[i]+ W*(sample-n->rate[i]);
						ewma = 1;
                                        } else if (interval >= conf.time_constant) {
						ns->rate[i] = sample;
						ewma = 2;
					} else {
						double w = W*(double)interval/conf.scan_interval;
						ns->rate[i] = n->rate[i] + w*(sample-n->rate[i]);
						ewma = 3;
					}
                                        
				done:;
				}
				break;
			}
		}
	}

	/* Remove old table */
	while (kern_db) {
		struct ifstat_ent *tmp = kern_db;
		kern_db = kern_db->next;
		free(tmp->name);
		free(tmp);
	};
	kern_db = is_new; /* The most recent devs from rt_netlink */
}

static int poll_client(int fd)
{
	struct pollfd p;
	char buf[128], *cmd, *pfx;
	ssize_t n;

	p.fd = fd;
	p.events = POLLIN;

	if (poll(&p, 1, 100) > 0
	    && (p.revents&POLLIN)) {
		n = read(fd, buf, sizeof(buf));
		if(n > 0) {
			buf[n] = 0;
			pfx = "scan_interval=";
			if((cmd = strstr(buf, pfx))) {
				conf.scan_interval = atoi(cmd+strlen(pfx));
				W = 1 - 1/exp(log(10)*(double)conf.scan_interval/conf.time_constant);
			}
			pfx = "time_constant=";
			if((cmd = strstr(buf, pfx))) {
				conf.time_constant = atoi(cmd+strlen(pfx));
				W = 1 - 1/exp(log(10)*(double)conf.scan_interval/conf.time_constant);
			}
			return 0;
		}
	}
	return -1;
}

#define T_DIFF(a,b) (((a).tv_sec-(b).tv_sec)*1000 + ((a).tv_usec-(b).tv_usec)/1000)

static void server_loop(int fd)
{
	struct timeval snaptime;
	struct pollfd p;
	
	memset(&snaptime, 0, sizeof(snaptime));
	
	p.fd = fd;
	p.events = p.revents = POLLIN;

	load_info();

	for (;;) {
		int status;
		int tdiff;
		struct timeval now;

		gettimeofday(&now, NULL);
		tdiff = T_DIFF(now, snaptime);

//		if (tdiff >= 0) { 
			update_db(tdiff);
			snaptime = now;
			tdiff = 0;
//		}
		if (poll(&p, 1, conf.scan_interval-tdiff) > 0
		    && (p.revents&POLLIN)) {
			int clnt = accept(fd, NULL, NULL);

			if (clnt >= 0) {
				pid_t pid;

				/*
				  We assume forking will be ok
				  so update database here not
				  have races with forked process
				*/

				gettimeofday(&now, NULL);
				tdiff = T_DIFF(now, snaptime);
//				if (tdiff >= min_interval) {
					update_db(tdiff);
					snaptime = now;
					tdiff = 0;
//				}
				poll_client(clnt);
				
				sprintf(info_source,
					"pid=%d sampling_interval=%d "
					"time_const=%d",
					getpid(),
					conf.scan_interval/1000,
					conf.time_constant/1000);

				if (children >= 5) {
					close(clnt);
				} else if ((pid = fork()) != 0) {

					if (pid>0) 
						children++;
					close(clnt);
				} else {
					FILE *fp = fdopen(clnt, "w");
					if (fp) {
						/* Write on clients socket */
						dump_raw_db(fp);
					}
					exit(0);
				}
			}
		}
		while (children && waitpid(-1, &status, WNOHANG) > 0)
			children--;
	}
}

int verify_forging(int fd)
{
	struct ucred cred;
	unsigned int olen = sizeof(cred);
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, (void*)&cred, &olen) ||
	    olen < sizeof(cred))
		return -1;
	if (cred.uid == getuid() || cred.uid == 0)
		return 0;
	return -1;
}

static void usage(void) __attribute__((noreturn));

static void usage(void)
{
        fprintf(stderr,
"Usage: ifstat2 [ -h?vVzrnasd:t: ] [ PATTERN [ PATTERN ] ]\n"
                );

        fprintf(stderr, " client options:\n");
        fprintf(stderr, "  -e extended statistics\n");
        fprintf(stderr, "  -f foreground\n");
        fprintf(stderr, "  -v print version\n");
        fprintf(stderr, "  -i verbose info\n");
        fprintf(stderr, "  -n disable formatting of output\n");
        fprintf(stderr, "  -h this help\n");

        fprintf(stderr, " daemon options;\n");
        fprintf(stderr, "  -d SECS -- scan interval in SECS seconds and daemonize\n");
        fprintf(stderr, "  -t SECS -- time constant for average calc [60] (t>d)\n");

        exit(-1);
}

int connect_server() 
{
	int fd;
	struct sockaddr_un sun;

	/* Setup for abstract unix socket */

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	sun.sun_path[0] = 0;
	sprintf(sun.sun_path+1, "ifstat%dv" VERSION, getuid());

	if((fd = socket(AF_UNIX, SOCK_STREAM, 0))==-1)
		return -1;
	
	if(connect(fd, (struct sockaddr*)&sun, sizeof(sun))) {
		strcpy(sun.sun_path+1, "ifstat0");
		if(connect(fd, (struct sockaddr*)&sun, sizeof(sun))) {
			close(fd);
			return -1;
		}

	}
	if(verify_forging(fd)) {
		printf("Forged server!\n");
		close(fd);
		exit(1);
	}
	
	return fd;
}

int server()
{
	int fd;
	struct sockaddr_un sun;

	/* Setup for abstract unix socket */

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	sun.sun_path[0] = 0;
	sprintf(sun.sun_path+1, "ifstat%dv" VERSION, getuid());

	if (conf.scan_interval == 0) 
		conf.scan_interval = DEFAULT_INTERVAL; 
		
	if (conf.time_constant == 0)
		conf.time_constant = DEFAULT_TIME_CONST;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror("ifstat: socket");
		return -1;
	}
	if (bind(fd, (struct sockaddr*)&sun, sizeof(sun)) < 0) {
		perror("ifstat: bind");
		return -1;
	}
	if (listen(fd, 5) < 0) {
		perror("ifstat: listen");
		return -1;
	}
	if(!conf.foreground) {
		if (fork()) {
			/* parent */
			close(fd);
			
			/* clear settings, already used by daemon */
			conf.time_constant = conf.scan_interval = 0;
			return 0;
		}
	}
	
	conf.time_constant *= 1000;
	conf.scan_interval *= 1000; 
	W = 1 - 1/exp(log(10)*(double)conf.scan_interval/conf.time_constant);
	
	chdir("/");
	if(!conf.foreground) {
		close(0); close(1); close(2);
		setsid();
	}
	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, sigchild);
	server_loop(fd);
	exit(0);
}

int push_config(int fd)
{
	char buf[256], *p;
	int n;

	p = buf;
	*p = 0;
	if(conf.time_constant) {
		n = sprintf(p, "time_constant=%d\n", conf.time_constant*1000);
		p+=n;
	}
	if(conf.scan_interval) {
		n = sprintf(p, "scan_interval=%d\n", conf.scan_interval*1000);
		p+=n;
	}
	write(fd, buf, strlen(buf));
	return 0;
}

int main(int argc, char *argv[])
{
	int ch;
	int fd;

	conf.min_interval = 20;
	
	while ((ch = getopt(argc, argv, "h?vVfid:t:ern")) != EOF) {
		switch(ch) {

		case 'n':
			conf.noformat++;
			break;
		case 'e':
			conf.show_errors = 1;
			break;
		case 'f':
			conf.foreground = 1;
			break;
		case 'd':
			conf.scan_interval = atoi(optarg);
			break;
		case 't':
			if (sscanf(optarg, "%d", &conf.time_constant) != 1 ||
			    conf.time_constant <= 0) {
				fprintf(stderr, "ifstat: invalid time constant divisor\n");
				exit(1);
			}
			break;

			
		case 'i':
			conf.verbose++;
			break;
		case 'v':
		case 'V':
			printf("ifstat2 utility, %s\n", VERSION);
			exit(0);
		case 'h':
		case '?':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	/* Client section */

	patterns = argv;
	npatterns = argc;

	while(1) {
		fd = connect_server();
		if(fd >= 0) {
			FILE *sfp;
		
			if( conf.time_constant || conf.scan_interval) {
				push_config(fd);
			} else {
				write(fd, "nop\n", 4);
			}

			sfp = fdopen(fd, "r");
			
			/* Read from daemon */
			
			if(sfp) {
				load_raw_table(sfp);
				fclose(sfp);
				dump_kern_db(stdout);
			}
			exit(0);
		}
		
		/* 
		 * No socket just start daemon
		 */
		if(server())
			break;
	}
	
	exit(1);
}
