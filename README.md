# Youpot summary

Youpot is a novel proxy-back pure honeypot for worms (and other adversaries).
While other honeypots will put a lot of effort into emulating some service,
we will just proxy the TCP connection back to the original host on the same 
destination port.

Author: Jacek Lipkowski SQ5BPF  <youpot@lipkowski.org>

For citation please use CITATION.cff


## Reasoning

Building a high interaction honeypot requires either writing a lot
of code to emulate a service, or modifying a some server to work
as a honeypot. Both is a lot of work, and leaves a big attack 
surface to take care of.

Building a pure honeypot requires one to set up a whole system/systems that
can be attacked, then set up cleanup procedures, instrumentation to get
the data from the honeypot etc. 


There is absolutely no way i will be able to emulate all services that a
worm might crave for it's replication. So let's just not do it.
A worm will come looking for a similar type of system it came from. 
So let's just give it exactly what it wants: proxy pack the TCP connection
back to the originating host.

The attacker is the honeypot :)


## Installing

Installing the software needs some basic linux admin/networking/development skills.

* Make sure you can run this service: you have the necssesary expertiese, you have permission from all involved parties etc. If in doubt consult a lawyer.
* Create a linux host, i used Debian bare-bones GNU/Linux 12.x, but other distros should do too
* Install the usual C developer tools, openssl dev library (apt install libssl-dev in Debian)
* Configure some way to have access to the host via something else than TCP from the internet. For example i set up an openvpn listening on UDP, and set up a dummy interface for sshd to listen on. But any other method will do (wire guard, tunneling sshd via tor etc).
* Turn off all TCP services running on the external interface
* Set up the firewall to redirect all TCP connections to 65534/tcp, please look at firewall.sh as an exmaple
* Reboot, make sure you can access this host over whatever admin interface you configured (for example ssh over openvpn).
 
* Create a youpot user
* As the youpot user do: cd ; git clone https://github.com/sq5bpf/youpot; cd youpot; make all
* Patch ~/youpot/utils/lib/python-\*/site-packages/sshmitm/session.py by adding   os._exit(os.EX_OK) at the end of def close(self) -> None:

Example unified diff:
```
--- session.py.orig     2025-05-31 00:29:25.164000000 +0200
+++ session.py  2025-05-26 18:04:55.372000000 +0200
@@ -360,6 +360,9 @@
             Colors.stylize(self.sessionid, fg("light_blue") + attr("bold")),
         )
         self.closed = True
+        #sq5bpf
+        print("sq5bpf: server exit")
+        os._exit(os.EX_OK)
```

* Run ~/youpot/youpot as the youpot user. Connect to youpot from some exteral host, and see if it proxies connections back to you (for example if you have 80/tcp running locally, then connecting to 80/tcp on the youpot host should connect you back to the IP you connected from on the same port)
* If all is fine, then run ~/youpot/youpot in some persistant way you like. For example i like to run it under screen, others will prefer tmux or a systemd service
* Remember to watch the number of free space and free inodes in the /home/youpot/youpot directory



## Debian specific instructions

Example debian 12.x install:

* install Debian 12 (i used debian 12.6 installer) - i used kvm with 2 cpus and 2GB ram, 
guided/entire disk. 
* In the debian installer "Choose software to install" deselect all options
* apt install net-tools tcpdump build-essential vim-nox aptitude openssh-server git libssl-dev
* adduser youpot
* Change /etc/network/interfaces to add a dummy interface:
```
source /etc/network/interfaces.d/*
auto lo
iface lo inet loopback
# this is the script that configures the firewall:
pre-up /etc/network/firewall.sh

# outside interface
auto ens192
iface ens192 inet static
address 1.2.3.4/24
gateway 1.2.3.1
dns-nameservers 8.8.8.8

# dummy interface for sshd to listen on
auto dummy0
iface dummy0 inet static
address 192.168.100.1
netmask 255.255.255.252
pre-up /sbin/modprobe dummy numdummies=4
```

* Change sshd config to listen on 192.168.100.1
Add this to /etc/ssh/sshd_config:
ListenAddress 192.168.100.1

* Install and configure openvpn, add a route to 192.168.100.1
* Reboot, check if you can connect via openvpn and login to ssh to 192.168.100.1
* As the youpot user do: cd ; git clone https://github.com/sq5bpf/youpot; cd youpot; make all


## Care and feeding

Youpot is currently hardcoded to run in /home/youpot/youpot. I will change this
in the future.

The logs are in /home/youpot/youpot/log:
* youpot.log - a generic log which shows what oupot is doing
* directories like IP/PORT/TIMESTAMP_TIMESTAMPus like: 1.2.3.4/23/1111_2222. this will include hexdump.log (a hexdump of the traffic), textdump.log (a raw dump of the traffic, nicer to look at than the hexdump), connection.json (json file with the traffic, easier to parse but harder to look at by a human), and optionally files/directories created by some protocol proxy (currently only ssm-mitm).

## Traffic modification

There is a simple facility to search/replace patterns in the traffic.


Place files like (where NNN is a number 0-99):
* pattern_NNN (pattern to search)
* replace_NNN (what to replace it with)
* descr_NNN (description of the replacement)

In directories like:
* /home/youpot/youpot/patterns_fromclient - replacing traffic from the client to the server
* /home/youpot/youpot/patterns_fromserver - replacing traffic from the server to the client
* Youpot will re-read the pattern files when it get a SIGHUP, so you can do: kill -HUP $(pidof youpot) after changing
* NOTE: there is no port match currenntly, no regexps etc. This is on the TODO list somewhere


Examples:

###### break STARTTLS in SMTP
```
echo -n 'STARTTLS' > /home/youpot/youpot/patterns_fromserver/pattern_1
echo -n 'STARTWTF' > /home/youpot/youpot/patterns_fromserver/replace_1
echo  'break STARTTLS from server' > /home/youpot/youpot/patterns_fromserver/descr_1
echo -n 'STARTTLS' > /home/youpot/youpot/patterns_fromclient/pattern_1
echo -n 'HELP WTF' > /home/youpot/youpot/patterns_fromclient/replace_1
echo  'break STARTTLS from client' > /home/youpot/youpot/patterns_fromclient/descr_1
echo -n 'STARTTLS' > /home/youpot/youpot/patterns_fromserver/pattern_1
echo -n 'STARTWTF' > /home/youpot/youpot/patterns_fromserver/replace_1
echo  'break STARTTLS from server' > /home/youpot/youpot/patterns_fromserver/descr_1
```
###### mess with HTTP headers
```
echo -n 'Accept-Encoding: gzip, deflate' > /home/youpot/youpot/patterns_fromclient/pattern_10
echo -n 'Accept-Encoding: wtf' > /home/youpot/youpot/patterns_fromclient/replace_10
echo 'turn off compression1' > /home/youpot/youpot/patterns_fromclient/descr_10

echo -n 'Accept-Encoding: gzip' > /home/youpot/youpot/patterns_fromclient/pattern_11
echo -n 'Accept-Encoding: wtf' > /home/youpot/youpot/patterns_fromclient/replace_11
echo 'turn off compression2' > /home/youpot/youpot/patterns_fromclient/descr_11
e
```



## Reporting

There are no reporting tools included with this software. Just parse the files yourself.

Some hints:

Look at unique ports we caught:
```
cd ~/youpot/log
ls -1d */* | cut -d / -f 2 | sort -u
```

Look at the raw dump or traffic for each port (press q for the next port):
```
cd ~/youpot/log
ls -1d */* | cut -d / -f 2 | sort -u |while read port; do (echo "#######  $port   #######"; cat */$port/*/textdump.log ) |less ; done
```






