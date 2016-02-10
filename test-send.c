#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>

#define NETLINK_LAF_USR NETLINK_USERSOCK
#define NETLINK_LAF_GRP 18

/* Linux header file confusion causes this to be undefined. */
#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#define MAX_PAYLOAD 1024

int open_netlink(void)
{
    int sock;
    struct sockaddr_nl addr;
    int group = NETLINK_LAF_GRP;

    sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_LAF_USR);
    if (sock < 0) {
        printf("sock < 0.\n");
        return sock;
    }

    memset((void *) &addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();

    if (setsockopt(sock, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group)) < 0) {
       	printf("setsockopt < 0\n");
       	return -1;
   	}

    return sock;
}

void send_event(int sock)
{
    struct sockaddr_nl nladdr;
    struct msghdr msg;
    struct iovec iov;
	struct nlmsghdr *nlh = NULL;
//	char buffer[] = "1";
	char buffer[] = "2";
//	char buffer[] = "3ping/curl/wget/nc/nmap/host/ssh/telnet/ftp/nslookup/ip/route/ntpdate/iptables/dhclient/ifconfig/iwconfig/wpa_supplicant/NetworkManager/crda/systemd-udevd/rpcbind/rpc.statd/avahi-daemon/minissdpd/colord-sane/cups-browsed/cupsd/sshd/pool/systemd/stunnel4/exim4/sendmail/http/gnome-settings-/clock-applet/mate-sensors-ap/mate-system-mon/xbrlapi/radare2/git/git-remote-http/dig/python/qtcreator/merssh/qemu-system-arm/vminfo/EMT/NAT/steam/steamwebhelper/arma3.i386/defcon.bin.x86/mb_warband_linu/ts3client_linux/eurotrucks2/X-Plane-x86_64/KSP.x86/tld.x86_64/PrisionArchitect/";
//	char buffer[] = "4Socket Thread/Resolver/Res~ver/DNS Res~er/MTPThread/Qt HTTP thread/Qt bearer threa/CHTTPClientThre/CIPCServer::Thr/CSteamControlle/Chrome_IOThread/WorkerPool/NetworkChangeNo/";
	int buflen = NLMSG_SPACE(strlen(buffer) + 1);
    int ret;

	memset(&msg,0,sizeof(msg));
	memset(&nlh,0,sizeof(nlh));

	memset(&nladdr, 0, sizeof(nladdr));
    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pid = 0; /* 0 - For Linux Kernel */
    nladdr.nl_groups = 0; /* unicast */

	nlh = (struct nlmsghdr *)malloc(buflen);
	memset(nlh, 0, NLMSG_SPACE(buflen));

	nlh->nlmsg_len = NLMSG_SPACE(buflen);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;

	strcpy(NLMSG_DATA(nlh), buffer);

	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *) &(nladdr);
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    printf("Ok, sending.\n");
    ret = sendmsg(sock, &msg, 0);

//	free(nlh);
}

int main(int argc, char *argv[])
{
    int nls;

    nls = open_netlink();
    if (nls < 0)
        return nls;

    send_event(nls);

	close(nls);

    return 0;
}