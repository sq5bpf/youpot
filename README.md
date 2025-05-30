# Youpot summary

Youpot is a novel proxy-back pure honeypot for worms (and other adversaries).
While other honeypots will put a lot of effort into emulating some service,
we will just proxy the TCP connection back to the original host on the same 
destination port.

## Reasoning

Building a high interaction honeypot requires either writing a lot
of code to emulate a service.

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

... TODO: will add some stuff here later.


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







