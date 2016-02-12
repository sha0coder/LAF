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

#include "laffun.h"

#define HELP_MSG	"Usage: %s [-uged] [-f config_file]\n\nFlags:\n\t-u\t\tUpdate the current LAF config.\n\t-g\t\tGet the current LAF config.\n\t-e\t\tEnable  the LAF firewall module\n\t-d\t\tDisable the LAF firewall module\n\t-f config_file\tThe config file path.\n"

char config_path[MAX_PATH] = "/etc/laf.cfg";

int main(int argc, char *argv[])
{
	char *whitelist_exact   = NULL;
	char *whitelist_similar = NULL;
	int  nls;
	int  c;
	char flag_u = 0, flag_g = 0;

	if (argc < 2) {
		fprintf(stderr, HELP_MSG, argv[0]);
		return EXIT_FAILURE;
	}

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
		read_event(nls, MSG_DONTWAIT);
		printf("\nsimilar whitelist: \n");
		send_event(nls, "2");
		read_event(nls, MSG_DONTWAIT);
	}

	/* close socket */
	close(nls);

	return 0;
}
