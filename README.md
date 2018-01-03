# sniffd

#Linux Ubuntu 16.04

1. A daemon should be implemented that sniffs packets from particular interface. It
saves ip addresses of incoming packets and number of packets from each ip.
2. Time complexity for ip search should be log(N).
3. Statistic should be persistent through reboots.
4. Command line interface (cli) should be implemented - another process that
interacts with the daemon.
5. The cli should support command:
a. start​ (packets are being sniffed from now on from default iface(eth0))
b. stop​ (packets are not sniffed)
c. show​ ​[ip]​ ​count​ ​(print number of packets received from ip address)
d. select​ ​iface​ ​[iface]​ ​(select interface for sniffing eth0, wlan0, ethN,
wlanN...)
e. stat​ [iface]​ show all collected statistics for particular interface, if iface
omitted - for all interfaces.
f. --help​ ​(show usage information)
6. Daemon could be started independently as well as through the cli.
