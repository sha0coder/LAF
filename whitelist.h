// Only following process names will be allowed to connect to LAN and internet
// (IPv4/6) the process need to have the name exactly equal than the whitelisted

char *whitelist_exact[] = {
	// BASE TOOLS
	"ping",
	"curl",
	"wget",
	"nc",
	"nmap",
	"host",
	"ssh",
	"telnet",
	"ftp",
	"nslookup",

	// NETWORK
	"ip",
	"route",
	"ntpdate",
	"iptables",
	"dhclient",
	"ifconfig",
	"iwconfig",
	"wpa_supplicant",
	"NetworkManager",
	"crda",

	// SYSTEM
	"systemd-udevd",
	"rpcbind",
	"rpc.statd",
	"avahi-daemon",
	"minissdpd",
	"colord-sane",
	"cups-browsed",
	"cupsd",
	"sshd",
	"pool",
	"systemd",
	"stunnel4",
	"exim4",
	"sendmail",
//	"cron",

	// DEBIAN
	"http",

	// DESKTOP
	"gnome-settings-",
	"clock-applet",
	"mate-sensors-ap",
	"mate-system-mon",
	"xbrlapi",

	// TOOLS
	"radare2",
	"git-remote-http",
	"dig",
	"python",
//	"tor",
//	"pipper",
//	"fauth",
//	"smtpEnum",
//	"exploit-db",

	// VIRTUALBOX
	"EMT",
	"NAT",

	// GAMES
	"steam",
	"steamwebhelper",
	"arma3.i386",
	"defcon.bin.x86",
	"mb_warband_linu",
	"ts3client_linux",
	"eurotrucks2",
	"X-Plane-x86_64",
	"KSP.x86",
	"tld.x86_64",
	"PrisionArchitect",

	NULL
};


// Processes whos name contains some of this words will be also allowed to
// connect to internet and LAN (ipv4 & ipv6) this words are compared with
// strstr()

char *whitelist_similar[] = {
	// FIREFOX & THUNDERBIRD2
	"Socket Thread",
	"Resolver",
	"Res~ver",
	"DNS Res~er",

	// QT
	"MTPThread",
	"Qt HTTP thread",
	"Qt bearer threa",

	// STEAM
	"CHTTPClientThre",
	"CIPCServer::Thr",
	"CSteamControlle",

	// CHROME
	"Chrome_IOThread",
	"WorkerPool",
	"NetworkChangeNo",

	NULL
};
