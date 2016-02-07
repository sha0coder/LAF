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

#define BLOCKED				-1
#define MAX_WHITELIST		255

#ifdef __x86_64__
# define __NR_socketcall	102
# define IA32_AF_INET		0x100000002
#elif defined(__i386__)
# define __NR_socket 		(__X32_SYSCALL_BIT + 41)
# define IA32_AF_INET		0x2
#else
# define IA32_AF_INET		0x2
#endif

// DEBUG 1 -> log allowed sockets
// LOG   0 -> don't log blocks | LOG 1 -> log blocks
static int DEBUG =			0;
static int LOG   =			1;
static int sysctl_min_val =		0;
static int sysctl_max_val =		1;
static struct ctl_table_header *busy_sysctl_header;

asmlinkage long (*old_socketcall) (int call, unsigned long __user *args);
asmlinkage int (*old_socket) (int domain, int type, int protocol);

unsigned long **st;
unsigned long **ia32_st;

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

		if (sct[__NR_ia32_lchown] == (unsigned long *) 0xffffffff810d5810) 
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
		if  (!isWhitelistedExact() && !isWhitelistedSimilar()) {
			printk(KERN_INFO "LAF: fam %02d proto %02d blocked: %s (%i:%i) parent: %s (%i)\n",domain,protocol,current->comm,current->pid,current->tgid,current->real_parent->comm,current->real_parent->pid);
			return BLOCKED;
		} else if (DEBUG)
			printk(KERN_INFO "LAF: fam %02d proto %02d allowed: %s (%i:%i) parent: %s (%i)\n",domain,protocol,current->comm,current->pid,current->tgid,current->real_parent->comm,current->real_parent->pid);
	}	

	return old_socket(domain,type,protocol);
}

asmlinkage long new_socketcall(int call, unsigned long __user *args) {

	switch (call) {
		case SYS_BIND:
		case SYS_SOCKET:
		if (args[0] == IA32_AF_INET) {	
			if  (!isWhitelistedExact() && !isWhitelistedSimilar()) {
				printk(KERN_INFO "LAF: call %02d fam 0x%lx blocked: %s (%i:%i) parent: %s (%i)\n",call,args[0],current->comm,current->pid,current->tgid,current->real_parent->comm,current->real_parent->pid);
				return BLOCKED;
			} else if (DEBUG)
				printk(KERN_INFO "LAF: call %02d fam 0x%lx allowed: %s (%i:%i) parent: %s (%i)\n",call,args[0],current->comm,current->pid,current->tgid,current->real_parent->comm,current->real_parent->pid);
		}
				
		break;
	}

	return old_socketcall(call,args);
}

static struct ctl_table laf_child_table[] = {
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
	/* register sysctl table */
	busy_sysctl_header = register_sysctl_table(kernel_main_table);
	if (!busy_sysctl_header) {
		printk(KERN_ALERT "Error: Failed to register kernel_main_table\n");
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

	hook();
	printk(KERN_INFO "LAF: Enabled\n");
			
	if (DEBUG)
		printk(KERN_INFO "LAF: st -> 0x%p - ia32_st -> 0x%p)\n",st,ia32_st);

	return 0;
}

static void __exit unload(void) {
	unHook();
	/* Unregister sysctl table */
	unregister_sysctl_table(busy_sysctl_header);
	printk(KERN_INFO "LAF: Disabled\n");
}

module_init(load);
module_exit(unload);

MODULE_LICENSE ("GPL");
MODULE_AUTHOR ("@sha0coder");

