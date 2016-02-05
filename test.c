#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>


int main(void) {

    //printf("PF_LOCAL %d\n",PF_LOCAL);
    //printf("PF_NETLINK %d\n",PF_NETLINK);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock<=0)
        printf("blocked\n");
    else
        printf("allowed\n");

} 
