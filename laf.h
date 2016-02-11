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

#define NETLINK_LAF_USR		NETLINK_USERSOCK
#define NETLINK_LAF_GRP		18

#define BLOCKED             -1
#define MAX_WHITELIST       4092

#define LAF_BLOCK_S         0
#define LAF_ALLOW_S         1
#define LAF_BLOCK_SC        2
#define LAF_ALLOW_SC        3

#define SYS_LCHOWN16		0xffffffff810d5810	/* sys_lchown16 */
