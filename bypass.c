#include <stdio.h>
#include <sys/socket.h>
#include <linux/net.h>

int main() {
	fd = socketcall(SYS_SOCKET,AF_INET,SOCK_STREAM,0);
	printf("socket: %d\n",fd);

	return 0;
}

