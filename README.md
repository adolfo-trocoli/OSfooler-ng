
<p align="center">
<img width="256" src="icon.png">
</p>
<br>

# OSfooler-NG
 [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
![Version: 2.0](https://img.shields.io/badge/version-2.0-blue.svg)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-blue.svg)](https://GitHub.com/segofensiva/OSfooler-ng/graphs/commit-activity)

*This version of osfooler-ng is aimed to provide a fully functioning python3 script with OS fingerprinting evasion and host detection evasion against nmap.*

An outsider can discover general information, such as which operating system a host is running, by checking default stack parameters, ambiguities in IETF RFCs, or non-compliant TCP/IP implementations in responses to malformed requests. By identifying the exact OS of a host, an attacker can launch a targeted and precise attack.

There are lot of reasons to hide your OS to the entire world:
 * Revealing your OS makes things easier to find and successfully run an exploit against any of your devices.
 * Having and unpatched or antique OS version is not very convenient for your company prestige. Imagine that your company is a bank and some users notice that you are running an unpatched box. They won't trust you any longer! In addition, these kind of 'bad' news are always sent to the public opinion.
 * Knowing your OS can also become more dangerous, because people can guess which applications are you running in that OS (data inference). For example if your system is a MS Windows, and you are running a database, it's highly likely that you are running MS-SQL.
 * It could be convenient for other software companies, to offer you a new OS environment (because they know which you are running).
 * And finally, privacy; nobody needs to know the systems you've got running.

OSfooler was presented at Blackhat Arsenal 2013. It was based on NFQUEUE, an iptables/ip6tables target that delegates packet decisions to userspace. It intercepted all traffic from the system to transparently modify TCP/IP flags used for OS fingerprinting.

OSfooler-NG is a complete rewrite: portable, efficient, and integrating all known techniques to detect and defeat:

 * Active remote OS fingerprinting and host detection: like Nmap
 * Commercial engines like Sourcefire’s FireSiGHT OS fingerprinting

Additional features include:
 * No kernel patching required
 * Simple UI and logging
 * Transparent to users, processes, and services
 * Active, passive, and combined detection/defeat modes
 * OS emulation support
 * Compatible with nmap and p0f v2 fingerprint databases
 * Undetectable by attackers


# Install
To install OSfooler-NG:
```
$ git clone https://github.com/adolfo-trocoli/OSfooler-ng.git
$ cd OSfooler-ng
$ python3 -m venv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
$ python3 osfooler-ng.py -V 
```

# Usage
## OS Fingerprinting
#### OS spoofing
To list available OSes, use `-n`:
```
$ python3 osfooler-ng.py -n
 [+] Please, select nmap OS to emulate
    + "2N Helios IP VoIP doorbell"
    ...
    + "ZyXEL ZyWALL 2 Plus firewall"
```

To emulate a specific OS, use `-m`:
```
$ python3 osfooler-ng.py -m "Sony Ericsson W705 or W715 Walkman mobile phone"
```

#### Search OS
Search within nmap's DB using `-s`:
```
$ python3 osfooler-ng.py -s playstation
```

#### Update database
Update nmap’s DB using `-u`:
```
$ python3 osfooler-ng.py -u
```

## Host detection evasion
#### Flag -z
Nmap’s host detection is a simpler form of fingerprinting. Probes are sent, and if replies are received, the host is marked as “up.”  
Evading this prevents follow-up scans and reduces unnecessary traffic.


These probes are of the following types:
- (-PE) ICMP Echo Request.
- (-PP) ICMP Timestamp Request.
- (-PM) ICMP Address Mask Request.
- (-PS \<ports>) TCP Syn.
- (-PA \<ports>) TCP Ack.
- (-PU \<ports>) UDP.
- (-PO \<proto. numbers>) IP with rare protocol numbers.
- (-PR) ARP.

By default, only a subset of these are sent, which are the following: `-PE -PS443 -PA80 -PP`

More information can be found in [nmap official book](https://nmap.org/book/host-discovery-techniques.html).

These same parameters can be used with -z flag, like the following examples. The "default" parameter can be used to evade default probes:
```
$ python3 osfooler-ng.py -z PE # won't answer to ICMP Echo Request
$ python3 osfooler-ng.py -z PP:PS400 # won't answer to ICMP Timestamp Request nor TCP Syn to port 400 
$ python3 osfooler-ng.py -z PA400,401,402 # won't answer to TCP ACK to ports 400,401,402
$ python3 osfooler-ng.py -z default # won't answer to default host detection probes
```

#### Drop Count or Timeout
By default, two packets are dropped per probe type (per IP). This mirrors nmap’s behavior (though undocumented). Count threshold should be chosen taking into account that legitimate client connections can be degraded or even fail if it is too high.

Use C (count) or T (timeout in seconds):

```
$ python3 osfooler-ng -z C4 # will drop 4 packets instead of 2
$ python3 osfooler-ng -z T3 # will drop packets for 3 seconds from the first one seen
$ python3 osfooler-ng -z PS80,443:C4

```


## Other Flags
  * `-v`: Print modified packets
  * `-i <iface>`: Select interface (default eth0)
  * `-V`: Show version and banner

# Tutorials
[Here](https://drive.google.com/file/d/1NgoYYE7Hgi_Kgx7FkjNfW_7IX5CCRsGU/view?usp=sharing) you can find a video demonstration (in Spanish) of the functionality.

# Authors
* **[Jaime Sánchez](https://www.seguridadofensiva.com) ([@segofensiva)](https://twitter.com/segofensiva)**
* **[Honeyhack-HQ](https://github.com/Honeyhack-HQ)**
* **[Adolfo Trocolí](https://es.linkedin.com/in/adolfo-trocol%C3%AD-naranjo-a07250224)  ([@adolfo-trocoli)](https://github.com/adolfo-trocoli)**

# License

This project is licensed under **GNU GPL v3.0** — see [LICENSE.md](LICENSE.md)

# Acknowledgments

* [Defcon China](https://defcon.org/html/dc-china-1/dc-cn-1-index.html), for leting me show this tool on [Demo Labs](https://defcon.org/html/dc-china-1/dc-cn-1-demolabs.html#segofensiva).
* All those people who have worked and released software on OS fingerprinting (attack and defense), specially [nmap](https://nmap.org/) & [p0f](lcamtuf.coredump.cx/), but also Xprobe, IP Personality etc.
* OSfooler-ng makes use of the [Scapy Project](https://scapy.net/) and [The netfilter.org "libnetfilter_queue" project](https://netfilter.org/projects/libnetfilter_queue/).
* Python 3 port was based on the work of HoneyHack-HQ.
* Host detection evasion was built by adolfo-trocoli.
