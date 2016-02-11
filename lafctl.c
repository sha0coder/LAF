/*
    LAF - Linux Application Firewall  (for linux Intel 32 and 64bits and ARM 32 bits)
	lafctl (user space control program)

    Copyright 2015-2016 by @sha0coder and @capi_x 

    Licensed under GNU General Public License 3.0 or later.
    Some rights reserved. See COPYING, AUTHORS.

    @license GPL-3.0 <http://www.gnu.org/licenses/gpl-3.0.txt>
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <linux/netlink.h>

#include "laf.h"

/* Linux header file confusion causes this to be undefined. */
#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#define DEBUG		0
#define MAX_PATH	1024
#define MAX_WL_NUMB 10240
#define MAX_WL_SIZE MAX_WL_NUMB * sizeof(char)

#define HELP_MSG	"Usage: %s [-uged] [-f config_file]\n\nFlags:\n\t-u\t\tUpdate the current LAF config.\n\t-g\t\tGet the current LAF config.\n\t-e\t\tEnable  the LAF firewall module\n\t-d\t\tDisable the LAF firewall module\n\t-f config_file\tThe config file path.\n"

char config_path[MAX_PATH] = "/etc/laf.cfg";

int open_netlink(void)
{
	int sock;
	struct sockaddr_nl addr;
	int group = NETLINK_LAF_GRP;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_LAF_USR);
	if (sock < 0) {
		fprintf(stderr, "error: can't open socket.\n");
		return -1;
	}

	memset((void *) &addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = getpid();

	if (setsockopt(sock, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group)) < 0) {
		fprintf(stderr, "error: can't open netlink.\n");
		close(sock);
	   	return -1;
   	}

	return sock;
}

void send_event(int sock, char *buffer)
{
	struct sockaddr_nl nladdr;
	struct msghdr msg;
	struct iovec iov;
	struct nlmsghdr *nlh = NULL;
	int buflen = NLMSG_SPACE(strlen(buffer) + 1);
	int ret;

	memset(&msg,    0, sizeof(msg));
	memset(&nlh,    0, sizeof(nlh));
	memset(&nladdr, 0, sizeof(nladdr));
	memset(&nladdr, 0, sizeof(nladdr));

	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid    = 0;	/* 0 = send to Linux kernel */
	nladdr.nl_groups = 0;	/* 0 = unicast */

	nlh = (struct nlmsghdr *)malloc(buflen);

	nlh->nlmsg_len = NLMSG_SPACE(buflen);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;

	strcpy(NLMSG_DATA(nlh), buffer);

	iov.iov_base = (void *)nlh;
	iov.iov_len  = nlh->nlmsg_len;
	msg.msg_name = (void *) &(nladdr);
	msg.msg_namelen = sizeof(nladdr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (DEBUG)
		printf("sending...\n");

	ret = sendmsg(sock, &msg, 0);

	return;
}

void read_event(int sock)
{
	struct sockaddr_nl nladdr;
	struct msghdr msg;
	struct iovec iov;
	char buffer[MAX_WL_NUMB];
	int  ret;

	iov.iov_base = (void *) buffer;
	iov.iov_len  = sizeof(buffer);
	msg.msg_name = (void *) &(nladdr);
	msg.msg_namelen = sizeof(nladdr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (DEBUG)
		printf("listening...\n");

	ret = recvmsg(sock, &msg, MSG_DONTWAIT);
	if (ret < 0)
		fprintf(stderr, "error: can't recv data.\n");
	else
		printf("%s\n", NLMSG_DATA((struct nlmsghdr *) &buffer));
}

int read_config (char *path, char *whitelist_exact, char *whitelist_similar) {
	FILE   *fp;
    char   *line = NULL;
    size_t  len = 0;
    ssize_t read;
	char    flag_exact   = 0;
	char    flag_similar = 0;
	int     wl_size_e    = 0;
	int     wl_size_s    = 0;

    fp = fopen(path, "r");
    if (fp == NULL) {
		fprintf(stderr, "error: can't read the file %s\n", path);
		return -1;
	}

    while ((read = getline(&line, &len, fp)) != -1) {
		if (line[0] == ' ' || line[0] == ';' || line[0] == '\n')
			continue;

		if (line[0] == '[') {
			line[read - 2] = '\0';
			line++;

			if (strcmp(line,"whitelist_exact") == 0) {
				flag_exact   = 1;
				flag_similar = 0;
			}

			if (strcmp(line,"whitelist_similar") == 0) {
				flag_exact   = 0;
				flag_similar = 1;
			}

			continue;
		}

		line[read - 1] = '/';

		if (wl_size_e + read >= MAX_WL_NUMB - 1 || wl_size_e + read >= MAX_WL_NUMB - 1) {
			fprintf(stderr, "error: the section in the config file is more than %i bytes.\n", MAX_WL_NUMB);
			fclose(fp);
			return -1;
		}

		if (flag_exact) {
			wl_size_e += read;
			strcat(whitelist_exact,line);
		}

		if (flag_similar) {
			wl_size_s += read;
        	strcat(whitelist_similar,line);
		}
    }

	fclose(fp);

	return 0;
}

int laf_set_sysctl(int status) {
	FILE *sys_enable_fp;
	sys_enable_fp = fopen("/proc/sys/kernel/laf/enabled", "w");

	if (sys_enable_fp > 0) {
		fprintf(sys_enable_fp, "%i\0", status);
		fclose (sys_enable_fp);
	} else
		return -1;

	return 0;
}

int main(int argc, char *argv[])
{
	char *whitelist_exact   = NULL;
	char *whitelist_similar = NULL;
	int  sys_enable;
	int  nls;
	char flag_u = 0, flag_g = 0;

	if (argc < 2) {
		fprintf(stderr, HELP_MSG, argv[0]);
		return EXIT_FAILURE;
	}

	int c;
	while ((c = getopt (argc, argv, ":f:uged")) != -1)
		switch (c) {
			case 'f':
				strncpy(config_path, optarg, MAX_PATH - 1);
				break;
			case 'u':
				flag_u = 1;
				break;
			case 'g':
				flag_g = 1;
				break;
			case 'e':
				laf_set_sysctl(1);
				break;
			case 'd':
				laf_set_sysctl(0);
				break;
			case '?':
				fprintf(stderr, HELP_MSG, argv[0]);
				return EXIT_FAILURE;
				break;
			default:
				fprintf(stderr, "%s: option -%c is missing a required argument\n", argv[0], optopt);
				return EXIT_FAILURE;
				break;
		}

	/* open socket */
	nls = open_netlink();
	if (nls < 0)
		return nls;

	/* send config */
	if (flag_u) {
		/* load wl */
		whitelist_exact   = malloc(MAX_WL_SIZE);
		whitelist_similar = malloc(MAX_WL_SIZE);

		whitelist_exact[0]   = '3';
		whitelist_similar[0] = '4';
		
		if (read_config(config_path, whitelist_exact, whitelist_similar) < 0) {
			close(nls);
			return EXIT_FAILURE;
		}

		/* send */
		send_event(nls, whitelist_exact);
		send_event(nls, whitelist_similar);

		/* free wl */
		free(whitelist_exact);
		free(whitelist_similar);

		/* sysctl kernel.laf.enable = 1 */
		laf_set_sysctl(1);
	}

	/* get config */
	if (flag_g) {
		printf("exact whitelist: \n");
		send_event(nls, "1");
		read_event(nls);
		printf("\nsimilar whitelist: \n");
		send_event(nls, "2");
		read_event(nls);
	}

	/* close socket */
	close(nls);

	return 0;
}
