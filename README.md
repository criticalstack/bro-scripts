# Due to changes in the priorities, this project is currently not being supported. The project is archived as of 11/17/21 and will be available in a read-only state. Please note, since archival, the project is not maintained or reviewed. #

bro-scripts
===========

Find us on the web at [www.CriticalStack.com](https://www.CriticalStack.com).  Check out our new [Intel Marketplace for Bro](https://intel.CriticalStack.com).

Repository includes a set of Bro scripts to be shared with the community.

[CVE-2014-6271 Exploit Detector](https://github.com/CriticalStack/bro-scripts/tree/cve-2014-6271/bash-cve-2014-6271)- The [CVE-2014-6271](http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-6271) vulnerability in the venerable Bourne-Again SHell (BASH) is rated as a **Level 10** allowing *full, unauthenticated* remote access to your systems; it's going to have some legs on it.  Expect it to crop up in a wide variety of exploit situations- POCs for HTTP are out with plenty more on the way.

   * 2014-9-26 Support added for DHCP hostname exploits

[Directional Logging for Files](https://github.com/criticalstack/bro-scripts/blob/master/files-log-by-direction/files-log-by-direction.bro)- modify the default behavior of Bro to allow you to log files as either inbound, outbound or internal.


