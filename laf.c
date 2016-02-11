/*
	LAF - Linux Application Firewall  (for linux Intel 32 and 64bits and ARM 32 bits)
	This firewall allows only communications made from allowed processes

	The detection and block is performed over the socket, AF_UNIX are allowed
	allways. 

	If other kind of socket is created (AF_INET,AF_INET6,...) if the
	processname is not in the whitelist the socket creation is canceled.

	Copyright 2015-2016 by @sha0coder and @capi_x 

	Licensed under GNU General Public License 3.0 or later.
	Some rights reserved. See COPYING, AUTHORS.

	@license GPL-3.0 <http://www.gnu.org/licenses/gpl-3.0.txt>
*/

#include <linux/module.h>	/* Needed by all modules	*/
#include <linux/kernel.h>	/* Needed for KERN_INFO		*/
#include <linux/init.h>		/* Needed for the macros	*/
#include <linux/limits.h>	/* ULLONG_MAX				*/
#include <linux/net.h>		
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/sched.h> 	/* current struct			*/
#include <linux/in.h>		/* sockaddr_in				*/
#include <linux/socket.h>
#include <linux/syscalls.h>
#include <linux/sysctl.h>
#include <linux/version.h>

#include <net/sock.h>

#include "laf.h"

#ifdef __x86_64__
# define __NR_socketcall	102
# define IA32_AF_INET		0x100000002
#elif defined(__i386__)
# ifndef  __NR_socket
#  define __NR_socket 		(__X32_SYSCALL_BIT + 41)
# endif
# define IA32_AF_INET		0x2
#else
# define IA32_AF_INET		0x2
#endif

/*
 * ENABLED 0 -> don't block sockets | ENABLED 1 -> block sockets
 * DEBUG   1 -> log allowed sockets
 * LOG     0 -> don't log blocks    | LOG 1 -> log blocks			*/
static int ENABLED =		0;
static int DEBUG   =		0;
static int LOG     =		1;

static int sysctl_min_val =	0;
static int sysctl_max_val =	1;
static struct ctl_table_header *busy_sysctl_header;

struct sock *laf_netlink = NULL;

char *whitelist_exact  [MAX_WHITELIST];
char *whitelist_similar[MAX_WHITELIST];

asmlinkage long (*old_socketcall) (int call, unsigned long __user *args);
asmlinkage int (*old_socket) (int domain, int type, int protocol);

unsigned long **st;
unsigned long **ia32_st;

static void laf_netlink_send(char * msg_out, unsigned long msg_out_size) {
	int res = 0;
	struct nlmsghdr *nlh;
	struct sk_buff  *skb_out;

	skb_out = nlmsg_new(NLMSG_ALIGN(msg_out_size), GFP_KERNEL);

	if (!skb_out) {
		printk(KERN_ALERT "LAF: Failed to allocate new skb.\n");
		kfree(msg_out);
		return;
	}

	nlh = nlmsg_put(skb_out, 0, 1, NLMSG_DONE, msg_out_size, 0);
	strncpy(nlmsg_data(nlh), msg_out, msg_out_size - 1);

	res = nlmsg_multicast(laf_netlink, skb_out, 0, NETLINK_LAF_GRP, GFP_KERNEL);

	/* a client must be listening, if not it will throw a -3 error (only in debug mode) */
	if ( res < 0 && DEBUG)
		printk(KERN_ALERT "LAF: Error %i sending netlink multicast.\n", res);

}

static void laf_get_whitelist (char **whitelist) {
	unsigned long msg_out_len = 0;
	char *msg_out;
	int i=0;

	for (i=0; i<MAX_WHITELIST; i++) {
		if (whitelist[i] == NULL)
			break;
		msg_out_len = msg_out_len + strlen(whitelist[i]) + 1;
	}

	if (msg_out_len == 0)
		return;

	/* alloc the string size + end null */
	msg_out = kmalloc(msg_out_len + 1,GFP_KERNEL);
	memset(msg_out, 0, msg_out_len);

	for (i=0; i<MAX_WHITELIST; i++) {
		if (whitelist[i] == NULL)
			break;
		strcat(msg_out,whitelist[i]);
		strcat(msg_out,"/");
	}

	if (DEBUG) {
		printk(KERN_INFO "LAF: print whitelist.\n");
		printk(KERN_INFO "LAF: %s\n", msg_out);
	}

	laf_netlink_send(msg_out, msg_out_len);

	kfree(msg_out);
}

static void laf_set_whitelist(char *msg_raw, char **whitelist) {
	int i = 0;
	char *token;
	char *msg_in  = msg_raw + 1;
	const char delim[] = "/";

	if (DEBUG)
		printk(KERN_INFO "LAF: update whitelist.\n");

	/* clean and kfree all whitelist matrix */
	for (i=0; i<MAX_WHITELIST; i++) {
		if (whitelist[i] != NULL) {
			kfree(whitelist[i]);
			whitelist[i]  = NULL;
		}
	}

	/* iter msg_in */
	token = strsep(&msg_in, delim);

	i = 0;
	while( token != NULL ) 
	{
		if (i >= (MAX_WHITELIST - 1)) {
			printk(KERN_INFO "LAF: whitelist limit reached (%i).\n", MAX_WHITELIST);
			break;
		}
		if (strlen(token) > 0) {
			if (DEBUG)
				printk(KERN_INFO "LAF: exact - %s\n", token );
			whitelist[i] = kmalloc(strlen(token) + 1, GFP_KERNEL);
			strcpy(whitelist[i],token);
			i++;
		}
		token = strsep(&msg_in, delim);
	}
	whitelist[i] = NULL;
}

static void laf_netlink_recv(struct sk_buff *skb) {
	struct nlmsghdr *nlh;
	char *msg_raw;

	/* the first msg_raw char is the command, the next is the payload and points to msg */
	nlh=(struct nlmsghdr*)skb->data;
	msg_raw = (char*)nlmsg_data(nlh);

	if (DEBUG)
		printk(KERN_INFO "LAF: recv from %d - %s\n", nlh->nlmsg_pid, msg_raw);

	switch (msg_raw[0]) {
		case '1':
			laf_get_whitelist(whitelist_exact);
			break;
		case '2':
			laf_get_whitelist(whitelist_similar);
			break;
		case '3':
			laf_set_whitelist(msg_raw, whitelist_exact);
			break;
		case '4':
			laf_set_whitelist(msg_raw, whitelist_similar);
			break;
		default:
			printk(KERN_INFO "LAF: recv -> WTF?!\n");
			break;
	}

	return;
}

static void laf_send_alert(int type, int domain, int protocol, char *comm, int pid, int tgid, char *parent_comm, int parent_pid ) {
	unsigned long new_msg_size = 0;
	unsigned long org_msg_size = 0;
	char *new_msg;

	/* kernel log */
	if (LOG)
	switch (type) {
		case LAF_BLOCK_S:
			printk(KERN_INFO "LAF: fam %02d proto %02d blocked: %s (%i:%i) parent: %s (%i)\n", domain, protocol, comm, pid, tgid, parent_comm, parent_pid);
			break;
		case LAF_ALLOW_S:
			printk(KERN_INFO "LAF: fam %02d proto %02d allowed: %s (%i:%i) parent: %s (%i)\n", domain, protocol, comm, pid, tgid, parent_comm, parent_pid);
			break;
		case LAF_BLOCK_SC:
			printk(KERN_INFO "LAF: call %02d fam 0x%x blocked: %s (%i:%i) parent: %s (%i)\n", domain, protocol, comm, pid, tgid, parent_comm, parent_pid);
			break;
		case LAF_ALLOW_SC:
			printk(KERN_INFO "LAF: call %02d fam 0x%x allowed: %s (%i:%i) parent: %s (%i)\n", domain, protocol, comm, pid, tgid, parent_comm, parent_pid);
			break;
	}

	/* netlink broadcast */
	org_msg_size = strlen(comm) + strlen(parent_comm) + ( sizeof(int) * 6 ) + 1; 
	new_msg_size = org_msg_size + 8; // 7 slash + 1 null

	new_msg = (char *) kmalloc(new_msg_size, GFP_KERNEL);
	sprintf(new_msg, "/%i/%i/%s/%i/%i/%s/%i", domain, protocol, comm, pid, tgid, parent_comm, parent_pid);

	laf_netlink_send(new_msg, new_msg_size);

	kfree(new_msg);
}

static unsigned long **acquire_sys_call_table(void)
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

#ifdef __x86_64__
static unsigned long **acquire_ia32_sys_call_table(void)
{
	unsigned long int offset = PAGE_OFFSET;
	unsigned long **sct;

	while (offset < ULLONG_MAX) {
		sct = (unsigned long **)offset;

		if (sct[__NR_ia32_lchown] == (unsigned long *) SYS_LCHOWN16) 
			return sct;

		offset += sizeof(void *);
	}
	
	return NULL;
}
#endif

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
#ifndef __arm__
    unsigned long value;
    asm volatile("mov %%cr0, %0" : "=r" (value));

    if(!(value & 0x00010000))
        return;

    asm volatile("mov %0, %%cr0" : : "r" (value & ~0x00010000));
#endif
}

static void enable_page_protection(void) {
#ifndef __arm__
    unsigned long value;
    asm volatile("mov %%cr0, %0" : "=r" (value));

    if((value & 0x00010000))
        return;

    asm volatile("mov %0, %%cr0" : : "r" (value | 0x00010000));
#endif
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
		if  (!isWhitelistedExact() && !isWhitelistedSimilar() && ENABLED) {
			laf_send_alert(LAF_BLOCK_S, domain,protocol,current->comm,current->pid,current->tgid,current->real_parent->comm,current->real_parent->pid);
			return BLOCKED;
		} else if (DEBUG)
			laf_send_alert(LAF_ALLOW_S, domain,protocol,current->comm,current->pid,current->tgid,current->real_parent->comm,current->real_parent->pid);
	}	

	return old_socket(domain,type,protocol);
}

asmlinkage long new_socketcall(int call, unsigned long __user *args) {

	switch (call) {
		case SYS_BIND:
		case SYS_SOCKET:
		if (args[0] == IA32_AF_INET) {	
			if  (!isWhitelistedExact() && !isWhitelistedSimilar() && ENABLED) {
				laf_send_alert(LAF_BLOCK_SC, call,args[0],current->comm,current->pid,current->tgid,current->real_parent->comm,current->real_parent->pid);
				return BLOCKED;
			} else if (DEBUG)
				laf_send_alert(LAF_ALLOW_SC, call,args[0],current->comm,current->pid,current->tgid,current->real_parent->comm,current->real_parent->pid);
		}
				
		break;
	}

	return old_socketcall(call,args);
}

static struct ctl_table laf_child_table[] = {
	{
		.procname		= "enabled",
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.data			= &ENABLED,
		.proc_handler	= &proc_dointvec_minmax,
		.extra1			= &sysctl_min_val,
		.extra2			= &sysctl_max_val,
	},
	{
		.procname		= "debug",
		.maxlen			= sizeof(int),
		.mode			= 0644,
		.data			= &DEBUG,
		.proc_handler	= &proc_dointvec_minmax,
		.extra1			= &sysctl_min_val,
		.extra2			= &sysctl_max_val,
	},
	{
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
		.procname		= "laf",
		.mode			= 0555,
		.child			= laf_child_table,
	},
	{}
};

static struct ctl_table kernel_main_table[] = {
{
		.procname		= "kernel",
		.mode			= 0555,
		.child			= laf_main_table,
	},
	{}
};

void unHook(void) {
	disable_page_protection();

	/* Reset old syscall table */
#ifndef __i386__
	st[__NR_socket]				= (void *)old_socket;
#endif
#ifndef __arm__
	ia32_st[__NR_socketcall]	= (void *)old_socketcall;
#endif

	enable_page_protection();
}

void hook(void) {
	disable_page_protection();

	/* Intel 64 bits and ARM sys_socket */
#ifndef __i386__
	old_socket		= (void *)st[__NR_socket];
	st[__NR_socket]	= (void *)new_socket;
#endif

	/* Intel 32 bit (real/emul) sys_socketcall */
#ifndef __arm__
	old_socketcall				= (void *)ia32_st[__NR_socketcall];
	ia32_st[__NR_socketcall]	= (void *)new_socketcall;
#endif

	enable_page_protection();
}


static int __init load(void) {

	/* netlink init */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0)
	laf_netlink = netlink_kernel_create(&init_net, NETLINK_LAF_USR, 0, laf_netlink_recv, NULL, THIS_MODULE);
#else
	struct netlink_kernel_cfg cfg = {
		.groups = NETLINK_LAF_GRP,
		.input  = laf_netlink_recv,
	};

	laf_netlink = netlink_kernel_create(&init_net, NETLINK_LAF_USR, &cfg);
#endif

	if (!laf_netlink) {
		printk(KERN_ALERT "LAF: Error creating netlink socket. (user: %i group: %x)\n",NETLINK_LAF_USR,NETLINK_LAF_GRP);
		return -EFAULT;
	}

	/* register sysctl table */
	busy_sysctl_header = register_sysctl_table(kernel_main_table);
	if (!busy_sysctl_header) {
		netlink_kernel_release(laf_netlink);
		printk(KERN_ALERT "LAF: Failed to register kernel_main_table\n");
		return -EFAULT;
	}

	/* load the syscall table addr in st */
	st		= acquire_sys_call_table();

	/* load the 32 bit emul sys_table on amd64 or the real 32 sys_table on ia32 */
#ifdef __x86_64__
	ia32_st = acquire_ia32_sys_call_table();
#else
	ia32_st = st;
#endif

	/* exec syscall hooks */
	hook();

	printk(KERN_INFO "LAF: Loaded\n");
			
	if (DEBUG)
		printk(KERN_INFO "LAF: st -> 0x%p - ia32_st -> 0x%p)\n",st,ia32_st);

	return 0;
}

static void __exit unload(void) {
	int i = 0;

	/* restore original syscalls */
	unHook();

	/* release netlink */
	netlink_kernel_release(laf_netlink);

	/* unregister sysctl table */
	unregister_sysctl_table(busy_sysctl_header);

	/* free all mem */
	for (i=0; i<MAX_WHITELIST; i++) {
		if (whitelist_exact[i] != NULL) {
			kfree(whitelist_exact[i]);
			whitelist_exact[i]  = NULL;
		}
		if (whitelist_similar[i] != NULL) {
			kfree(whitelist_similar[i]);
			whitelist_similar[i]  = NULL;
		}
	}

	printk(KERN_INFO "LAF: Unloaded\n");
}

module_init(load);
module_exit(unload);

MODULE_LICENSE ("GPL");
MODULE_AUTHOR ("@sha0coder");

