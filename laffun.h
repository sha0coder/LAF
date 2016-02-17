#include <sys/socket.h>

/* Linux header file confusion causes this to be undefined. */
#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#define DEBUG       0
#define MAX_PATH    1024
#define MAX_WL_NUMB 10240
#define MAX_WL_SIZE MAX_WL_NUMB * sizeof(char)
#define LAF_DBUS_SERIAL	14731337

int  open_netlink(void);
void send_event(int, char *);
void read_event(int, int);
void read_event_buf( int, int, char *, size_t);
int  read_config (char *, char *, char *);
int  laf_add_whitelist(int, char *, char *);
int  laf_set_sysctl(int);

