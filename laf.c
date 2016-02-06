/*
	LAF - Linux Application Firewall  (for linux 64bits)
	This firewall allows only communications made from allowed processes

	The detection and block is performed over the socket, AF_UNIX are allowed
	allways. 

	If other kind of socket is created (AF_INET,AF_INET6,...) if the
	processname is not in the whitelist the socket creation is canceled.

	by @sha0coder and @capi_x
*/

#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>		/* Needed for the macros */
#include <linux/limits.h>	// ULLONG_MAX
#include <linux/net.h>		
#include <linux/sched.h> 	// current struct
#include <linux/in.h>		// sockaddr_in
#include <linux/socket.h>
#include <linux/syscalls.h>
#include <linux/sysctl.h>

#include "whitelist.h"

#define __NR_socketcall		102
#define __NR_connect		42
//#define __NR_socket 		4

#define BLOCKED				-1
#define MAX_WHITELIST		255

// DEBUG 1 -> log allowed sockets
// LOG   0 -> don't log blocks | LOG 1 -> log blocks
static int DEBUG =			0;
static int LOG   =			1;
static int sysctl_min_val =		0;
static int sysctl_max_val =		1;
static struct ctl_table_header *busy_sysctl_header;

//asmlinkage long (*old_socketcall) (int call, unsigned long __user *args);
//asmlinkage int (*old_connect) (int sockfd, const struct sockaddr *addr, long addrlen);
asmlinkage int (*old_socket) (int domain, int type, int protocol);

unsigned long **st;

static unsigned long **aquire_sys_call_table(void)
{
	unsigned long int offset = PAGE_OFFSET;
	unsigned long **sct;

	while (offset < ULLONG_MAX) {
		sct = (unsigned long **)offset;

		if (sct[__NR_close] == (unsigned long *) sys_close) 
			return sct;

		offset += sizeof(void *);
	}
	
	return NULL;
}

int isWhitelistedSimilar(void) {
	int i;

	for (i=0; i<MAX_WHITELIST; i++) {

		if (whitelist_similar[i] == NULL)
			return 0;

		if (strstr((char *)(current->comm), whitelist_similar[i]) != NULL)
			return 1;
	}

	return 0;
}

int isWhitelistedExact(void) {
	int i;

	for (i=0; i<MAX_WHITELIST; i++) {

		if (whitelist_exact[i] == NULL)
			return 0;

		if (strcmp(whitelist_exact[i], (char *)(current->comm)) == 0)
			return 1;
	}

	return 0;
}

static void disable_page_protection(void) {
    unsigned long value;
    asm volatile("mov %%cr0, %0" : "=r" (value));

    if(!(value & 0x00010000))
        return;

    asm volatile("mov %0, %%cr0" : : "r" (value & ~0x00010000));
}

static void enable_page_protection(void) {
    unsigned long value;
    asm volatile("mov %%cr0, %0" : "=r" (value));

    if((value & 0x00010000))
        return;

    asm volatile("mov %0, %%cr0" : : "r" (value | 0x00010000));
}

/* new_socket - function to block or allow a new socket
 * --
 * Those family/type are whitelisted because cannot use IPv4/6:
 *
 * +============+===========================+====+
 * | FAMILY		| PROTOCOLS					|TYPE|
 * +============+===========================+====+
 * | AF_UNIX	| ALL PROTOCOLS			    | -- |
 * +------------+---------------------------+----+
 * | AF_NETLINK	| NETLINK_AUDIT				| 09 |
 * |			| NETLINK_KOBJECT_UEVENT	| 15 |
 * +------------+---------------------------+----+
 *
 * This function also check if the socket is whitelisted in the
 * file: whitelist.h
 */ 

asmlinkage int new_socket(int domain, int type, int protocol) {
	if ((domain != AF_UNIX) && ((domain != AF_NETLINK) && (protocol != 9) && (protocol != 15))) {
		if  (!isWhitelistedExact() && !isWhitelistedSimilar()) {
			printk(KERN_INFO "LAF: fam %02d proto %02d blocked: %s (%i:%i) parent: %s (%i)\n",domain,protocol,current->comm,current->pid,current->tgid,current->real_parent->comm,current->real_parent->pid);
			return BLOCKED;
		}
		if (DEBUG)
			printk(KERN_INFO "LAF: fam %02d proto %02d allowed: %s (%i:%i) parent: %s (%i)\n",domain,protocol,current->comm,current->pid,current->tgid,current->real_parent->comm,current->real_parent->pid);
	}	

	return old_socket(domain,type,protocol);
}

/*
asmlinkage int new_connect(int sockfd, const struct sockaddr *addr, long addrlen) {
	if (((struct sockaddr_in *)addr)->sin_family == AF_INET6)
		return -1;
	
	if (((struct sockaddr_in *)addr)->sin_family == AF_INET) {
		if (!isWhitelistedExact()) {
			if (LOG)
				printk(KERN_INFO "LAF blocked %s\n",current->comm);
			return -1;
			//return BLOCKED;
		}
	}

	return old_connect(sockfd,addr,addrlen);
}

asmlinkage long new_socketcall(int call, unsigned long __user *args) {

	printk(KERN_INFO "new_socketcall %d",call);

	switch (call) {
		case SYS_BIND:
		case SYS_CONNECT:
			printk(KERN_INFO "LAF: socketcall connect/bind proc:%s\n",current->comm);
			return -1;
			
			printk(KERN_INFO "fam:%d proc:%s\n",((struct sockaddr_in *)args[1])->sin_family,current->comm);
			if (((struct sockaddr_in *)args[1])->sin_family != 1)
				if (!isWhitelistedExact())
					return BLOCKED;
			
			break;

		case SYS_SENDTO:
		case SYS_RECVFROM:
			printk(KERN_INFO "LAF: socketcall sendto/recvfrom proc:%s\n",current->comm);
			return -1;
			
			printk(KERN_INFO "fam:%d proc:%s\n",((struct sockaddr_in *)args[1])->sin_family,current->comm);
			if (((struct sockaddr_in *)args[4])->sin_family != 1)
				if (!isWhitelistedExact())
					return BLOCKED;
			break;

	
		case SYS_SENDMSG:
		case SYS_RECVMSG:
			break;

		case SYS_ACCEPT:
		case SYS_SEND:
		case SYS_RECV:
		case SYS_LISTEN:
			break;

		case SYS_SOCKET:
        case SYS_GETSOCKNAME:
        case SYS_GETPEERNAME:
        case SYS_SOCKETPAIR:
        case SYS_SHUTDOWN:
        case SYS_SETSOCKOPT:
        case SYS_GETSOCKOPT:
        	break;

	}

	return old_socketcall(call,args);
}
*/

static struct ctl_table laf_child_table[] = {
	{
//		.ctl_name		= CTL_UNNUMBERED,
		.procname		= "debug",
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.data			= &DEBUG,
		.proc_handler	= &proc_dointvec_minmax,
		.extra1			= &sysctl_min_val,
		.extra2			= &sysctl_max_val,
	},
	{
//		.ctl_name		= CTL_UNNUMBERED,
		.procname		= "log",
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.data			= &LOG,
		.proc_handler	= &proc_dointvec_minmax,
		.extra1			= &sysctl_min_val,
		.extra2			= &sysctl_max_val,
	},
	{}
};

static struct ctl_table laf_main_table[] = {
{
//		.ctl_name		= CTL_KERN,
		.procname		= "laf",
		.mode			= 0555,
		.child			= laf_child_table,
	},
	{}
};

static struct ctl_table kernel_main_table[] = {
{
//		.ctl_name		= CTL_KERN,
		.procname		= "kernel",
		.mode			= 0555,
		.child			= laf_main_table,
	},
	{}
};

void unHook(void) {
	disable_page_protection();
	st[__NR_socket] = (void *)old_socket;
	enable_page_protection();
}

void hook(void) {
	disable_page_protection();
	old_socket = (void *)st[__NR_socket];
	st[__NR_socket] = (void *)new_socket;
	enable_page_protection();
}


static int __init load(void) {
	/* register sysctl table */
	busy_sysctl_header = register_sysctl_table(kernel_main_table);
	if (!busy_sysctl_header) {
		printk(KERN_ALERT "Error: Failed to register kernel_main_table\n");
		return -EFAULT;
	}

	/* load the syscall table addr in st */
	st = aquire_sys_call_table();
	hook();
	printk(KERN_INFO "LAF Enabled\n");
	return 0;
}

static void __exit unload(void) {
	unHook();
	/* Unregister sysctl table */
	unregister_sysctl_table(busy_sysctl_header);
	printk(KERN_INFO "LAF Disabled\n");
}

module_init(load);
module_exit(unload);

MODULE_LICENSE ("GPL");
MODULE_AUTHOR ("@sha0coder");

