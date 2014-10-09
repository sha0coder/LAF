

// put here your syscall table address  (grep sys_call_table /proc/kallsyms)
unsigned long **st = (unsigned long **)0xffffffff81801400;


#define LOG 1 // 0 -> don't log blocks   1 -> log blocks

// Only following process names will be allowed to connect to LAN and internet(ipv4 & ipv6), 
// the process need to have the name exactly equal than the whitelisted.

char *whitelist_exact[] = {
	// BASE TOOLS
	"tor",
	"ping",
	"curl",
	"wget",
	"nc",
	"nmap",
	"host",
	"ssh",
	"ftp",

	// HACK TOOLS
	"pipper",
	"fauth",
	"smtpEnum",
	"exploit-db",
	"python",
	"python2",
	"sudo",

	// SYSTEM 
	"nslookup",
	"systemd-udevd",

	// FIREFOX & THUNDERBIRD
	"dnsmasq",


	NULL
};


// Processes whos name contains some of this words will be also allowed to connect to internet and LAN (ipv4 & ipv6)
// this words are compared with strstr()

char *whitelist_similar[] = {
	// FIREFOX & THUNDERBIRD2
	"Socket Thread",
	"Resolver",

	// CHROME
	"Chrome_IOThread",
	"WorkerPool",
	"NetworkChangeNo",
	NULL
};
