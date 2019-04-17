&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
# IPK Projekt 2 - Varianta OMEGA: Scanner síťových služeb

#### Autor: Simon Kobyda, FIT VUTBR

[![N|Solid](https://www.fit.vutbr.cz/images/fitnewz.png)](https://www.fit.vutbr.cz/)
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;

## Špecifikácia

Program oskenuje zvovené porty, ktoré potom vyhodnotí na closed, open alebo filtered. 

## Technické informácie

* __Programovací jazyk__: C
* __Použité sieťové knižnice__: 
```c
#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
```

## Stručný popis lifecyklu programu (výcuc naštudovaných informácii):

- Program naparsuje vstupné argumenty, z ktorých zistí TCP a UDP porty, interface a cieľovú adresu. Ak je cieľová adresa zadaná pomocou názvu domény, tak tú prekonvertuje na IP adresu.
- Nájde sa prvý interface pomocou funkcie __pcap_lookupdev__. V prípade, ak je cieľová doména loopback, tak sa interface nastaví na __lo__
- Zistia sa bližšie informácie pomocou funkcie __pcap_lookupnet__
- Handler na odchytávanie packetov sa vytvorí pomocou __pcap_open_live__
- Vytvorí sa socket typu __SOCK_RAW__
- Pre každý port sa naplnía __hlavičky headerov__ (napr. SIN, TCP, IP...)
- Vytvorí filterovací výraz na filtrovanie odchytených packetov. Ten sa skompiluje a nastaví (__pcap_compile pcap_setfilter__)
- Je odoslaný packet pomocou __sendto__
- Jednotlivé packety sa čítajú pomocou __pcap_next__, a podľa hodnoty ich flagov sa určite stav portu

## Testovanie:

Na testovanie programu sa využili open-source software: grafický nástroj Wireshark a konzolový nástroj nmap.
Na testovanie scannovania portov na vzdialenom serveri sa využil server doménz www.nemeckay.net.

## Návody a bibliografia:

Linux manual pages
https://www.security-portal.cz/clanky/jednoduch%C3%BD-tcpudp-scanner-v-c
https://www.tcpdump.org/pcap.html
https://www.binarytides.com/raw-sockets-c-code-linux/
