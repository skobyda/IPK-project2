#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <strings.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>

#include <unistd.h>

pcap_t *handle;

/*
 parametre vsetky na string
 porty na ints
 -> PORT INT

 Adresa ciela, vzdy potrebujeme previest na IP adresu. Domain name skonvertovat na IP cez getaddrname.
 Ip adresu drzat ako string.
 -> DESTINATION IP as STRING

 zistit interface ak je dany, ak nie tak zistit prvy interface (device)
 ak je destination IP localhost, tak interface bude lo
 -> INTERACE as STRING

 zistit vlastnu IP adresu
 -> SOURCE IP as STRING

 * */

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

    /* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

    // SOURCE: https://www.tcpdump.org/pcap.html
	/* Ethernet header */
	struct sniff_ethernet {
		u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		u_short ether_type; /* IP? ARP? RARP? etc */
	};

	/* IP header */
	struct sniff_ip {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		struct in_addr ip_src,ip_dst; /* source and dest address */
	};
	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
	#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	/* TCP header */
	typedef u_int tcp_seq;

	struct sniff_tcp {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
    };


/*
    96 bit (12 bytes) pseudo header needed for tcp header checksum calculation
*/
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

// Source: https://www.binarytides.com/raw-sockets-c-code-linux/
unsigned short csum(unsigned short *ptr,int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

void my_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */

    u_int size_ip;
    u_int size_tcp;

    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        exit(1);
    }
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        exit(1);
    }

    if ((tcp->th_flags & TH_SYN) && (tcp->th_flags & TH_ACK))
        printf("open\n");
    if ((tcp->th_flags & TH_RST) && (tcp->th_flags & TH_ACK))
        printf("closed\n");
}

void parge_arguments(int argc, char *argv[], char *arg_dest_addr, int *arg_tcp_ports, int *arg_udp_ports, char **iface, int *tcp_len, int *udp_len) {
    for (int i = 1; i < argc - 1; i += 2) {
        if (strcmp(argv[i], "-pt") == 0) {
            char *pt = strtok (argv[i + 1],",");
            int j = 0;
            while (pt != NULL) {
                int a = atoi(pt);
                arg_tcp_ports[j] = a;
                pt = strtok (NULL, ",");
                j++;
                (*tcp_len)++;
            }
        } else if (strcmp(argv[i], "-pu") == 0) {
            char *pt = strtok (argv[i + 1],",");
            int j = 0;
            while (pt != NULL) {
                int a = atoi(pt);
                arg_udp_ports[j] = a;
                pt = strtok (NULL, ",");
                j++;
                (*udp_len)++;
            }
        } else if (strcmp(argv[i], "-i") == 0) {
            *iface = malloc(sizeof(char) * 100);
            strcpy(*iface, argv[i + 1]);
        } else {
            // TODO error
        }
    }

    strcpy(arg_dest_addr, argv[argc-1]);

    struct sockaddr_in tmp;
    if (strcmp(arg_dest_addr, "localhost") == 0) {
        strcpy(arg_dest_addr, "127.0.0.1");
    } else if (inet_pton(AF_INET, arg_dest_addr, &(tmp.sin_addr)) == 0) {
        struct hostent *he;
        struct in_addr **addr_list;
        int i;

        if ((he = gethostbyname(arg_dest_addr)) == NULL) {
            herror("Error: Could not convert hostname to IP");
            exit(1);
        }

        addr_list = (struct in_addr **) he->h_addr_list;

        for(i = 0; addr_list[i] != NULL; i++) {
            strcpy(arg_dest_addr , inet_ntoa(*addr_list[i]) );
            break;
        }
    }
}

// Source: https://www.binarytides.com/raw-sockets-c-code-linux/
void fill_ip_header(struct iphdr *iph, char *data, char *source_ip, struct sockaddr_in sin, char *datagram) {
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
    iph->id = htonl (54321);    //Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;     //Set to 0 before calculating checksum
    iph->saddr = inet_addr ( source_ip );   //Spoof the source ip address
    iph->daddr = sin.sin_addr.s_addr;
    iph->check = csum ((unsigned short *) datagram, iph->tot_len);
}

// Source: https://www.binarytides.com/raw-sockets-c-code-linux/
void fill_tcp_header(struct tcphdr *tcph, int tcp_port) {
    tcph->source = htons (42);
    tcph->dest = htons (tcp_port);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5; //tcp header size
    tcph->fin=0;
    tcph->syn=1;
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons (5840);    /* maximum allowed window size */
    tcph->check = 0;    //leave checksum 0 now, filled later by pseudo header
    tcph->urg_ptr = 0;
}

// Source: https://www.binarytides.com/raw-sockets-c-code-linux/
void fill_pseudo_header(struct pseudo_header *psh, char *source_ip, struct sockaddr_in sin, char *data) {
    psh->source_address = inet_addr( source_ip );
    psh->dest_address = sin.sin_addr.s_addr;
    psh->placeholder = 0;
    psh->protocol = IPPROTO_TCP;
    psh->tcp_length = htons(sizeof(struct tcphdr) + strlen(data) );
}

void alarm_handler(int sig) {
    pcap_breakloop(handle);
}


// Source: https://www.tcpdump.org/pcap.html
int main(int argc, char *argv[]) {
    int *arg_tcp_ports = malloc(sizeof(int) * 100);
    int *arg_udp_ports = malloc(sizeof(int) * 100);
    int arg_tcp_ports_len = 0;
    int arg_udp_ports_len = 0;
    char *arg_dest_addr = malloc(sizeof(char) * 100);
    char *arg_source_addr = "127.0.0.1";
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    int sock;

    char *iface = NULL;
    parge_arguments(argc, argv, arg_dest_addr, arg_tcp_ports, arg_udp_ports, &iface, &arg_tcp_ports_len, &arg_udp_ports_len);

    // PCAP LOOKUPDEV
    if (strcmp(arg_dest_addr, "127.0.0.1")) {
        if (!iface) {
            dev = pcap_lookupdev(errbuf);
            if (dev == NULL) {
                fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
                exit(1);
            }
        } else {
            dev = iface;
        }
    } else {
        dev = "lo"; //TODO
    }

    // PCAP LOOKUPNET
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    // PCAP OPEN_LIVE
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(1);
    }

    // SOCKET CREATION
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock == -1) {
        printf("Error opening socket\n");
        exit(1);
    }

    for (int i = 0; i < arg_tcp_ports_len; i++) {
        //DECLARATIONS
        char datagram[4096] , source_ip[32] , *data , *pseudogram;
        memset (datagram, 0, 4096);
        struct iphdr *iph = (struct iphdr *) datagram;
        struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
        struct sockaddr_in sin;
        struct pseudo_header psh;

        //DATA - fill random data
        data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
        strcpy(data , "Did you every hear the tragedy of Darth Plagueis the Wise?");
        strcpy(source_ip , arg_source_addr);

        //SIN
        sin.sin_family = AF_INET;
        sin.sin_port = htons(arg_tcp_ports[i]);
        sin.sin_addr.s_addr = inet_addr (arg_dest_addr);

        //IP HEADER
        fill_ip_header(iph, data, source_ip, sin, datagram);

        //TCP HEADER
        fill_tcp_header(tcph, arg_tcp_ports[i]);

        //PSEUDO HEADER
        fill_pseudo_header(&psh, source_ip, sin, data);

        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
        pseudogram = malloc(psize);
        memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + strlen(data));
        tcph->check = csum( (unsigned short*) pseudogram , psize);
        int one = 1;
        const int *val = &one;

        //FILTER EXPRESSION FOR PCAP
        char* filter_exp = malloc(sizeof(char) * 40);
        sprintf(filter_exp, "tcp src port %d and tcp dst port 42", arg_tcp_ports[i]);

        //PCAP COMPILE
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            exit(1);
        }

        //PCAP FILTER
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            exit(1);
        }

        //SET SOCKET
        if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) {
            perror("Error setting IP_HDRINCL");
            exit(1);
        }

        //SEND PACKET
        if (sendto (sock, datagram, iph->tot_len , 0, (struct sockaddr *) &sin, sizeof (sin)) < 0) {
            perror("sendto failed");
        }

        printf("%d/dcp: ",arg_tcp_ports[i]);
        //PCAP LOOP
        // pcap_loop(handle, 1, my_handler, NULL);
        bool try_filtered = false;
        struct pcap_pkthdr header;
        const u_char *packet;

        while(42) {

            alarm(1);
            signal(SIGALRM, alarm_handler);

            packet = pcap_next(handle, &header);

            if (packet != NULL) {
                const struct sniff_ip *ip; /* The IP header */
                const struct sniff_tcp *tcp; /* The TCP header */

                u_int size_ip;
                u_int size_tcp;

                ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
                size_ip = IP_HL(ip)*4;
                if (size_ip < 20) {
                    printf("   * Invalid IP header length: %u bytes\n", size_ip);
                    exit(1);
                }
                tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
                size_tcp = TH_OFF(tcp)*4;
                if (size_tcp < 20) {
                    printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                    exit(1);
                }

                if ((tcp->th_flags & TH_SYN) && (tcp->th_flags & TH_ACK)) {
                    printf("open\n");
                    break;
                }
                if ((tcp->th_flags & TH_RST) && (tcp->th_flags & TH_ACK)) {
                    printf("closed\n");
                    break;
                }
            } else if (try_filtered) {
                printf("filtered\n");
                break;
            } else {
                try_filtered = true;
                continue;
            }
        }
    }
    pcap_close(handle);

    return(0);
}
