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

    if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        printf("bind < 0.\n");
        return -1;
    }

   	if (setsockopt(sock, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group)) < 0) {
       	printf("setsockopt < 0\n");
       	return -1;
   	}

    return sock;
}

void read_event(int sock)
{
    struct sockaddr_nl nladdr;
    struct msghdr msg;
    struct iovec iov;
    char buffer[65536];
    int ret;

    iov.iov_base = (void *) buffer;
    iov.iov_len = sizeof(buffer);
    msg.msg_name = (void *) &(nladdr);
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    printf("Ok, listening.\n");
    ret = recvmsg(sock, &msg, 0);
    if (ret < 0)
        printf("ret < 0.\n");
    else
        printf("Received message payload: %s\n", NLMSG_DATA((struct nlmsghdr *) &buffer));
}

int main(int argc, char *argv[])
{
    int nls;

    nls = open_netlink();
    if (nls < 0)
        return nls;

    while (1)
        read_event(nls);

	close(nls);

    return 0;
}
