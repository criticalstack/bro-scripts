# Copyright (c) 2014 Critical Stack LLC.  All Rights Reserved.
# Liam Randall (@Hectaman)

# Set of detection routines to monitor for CVE-2014-6271

# CHANGES:
#	2014-9-7 Initial support for http header vector via mod_cgi
#	2014-9-25 Added support for ignoring subnets to subnets
#	2014-9-26 Support for dhcp hostname- bro dhcp analyzer does not support other dhcp options :(

module Bash;

export {
	redef enum Notice::Type += {
		## Indicates that a host may have attempted a bash cgi header attack
		HTTP_Header_Attack,
		DHCP_hostname_Attack,
		DHCP_other_Attack,
	};

	# exclude hosts or entire networks from being tracked as potential "scanners".
	# index is conneciton subnet originators, yield is connection subnet responders
	const ignore_scanners: table[subnet] of subnet &redef;

	# what we are looking for on the exploit
	const shellshock = /\x28\x29\x20\x7b\x20/ &redef;
 

}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=3
	{

	if ( c$id$orig_h in ignore_scanners && c$id$resp_h in ignore_scanners[c$id$orig_h] )
		return;

	if ( is_orig )
		{
		if ( shellshock in value)
			{
			NOTICE([$note=Bash::HTTP_Header_Attack,
				$conn=c,
				$msg=fmt("%s may have attempted to exploit CVE-2014-6271, bash environment variable attack, via HTTP mod_cgi header against %s submitting \"%s\"=\"%s\"",c$id$orig_h, c$id$resp_h, name, value),
				$identifier=c$uid]);
			}
		}
	}

event dhcp_offer(c: connection, msg: dhcp_msg, mask: addr, router: dhcp_router_list, lease: interval, serv_addr: addr, host_name: string)
{
	if ( shellshock in host_name )
			NOTICE([$note=Bash::DHCP_hostname_Attack,
				$conn=c,
				$msg=fmt("%s may have attempted to exploit CVE-2014-6271, bash environment variable attack, via dhcp hostname against %s submitting \"hostname\"=\"%s\"",c$id$orig_h, c$id$resp_h, host_name),
				$identifier=c$uid]);
}


