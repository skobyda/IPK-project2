#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/tcp.h> // Provides declarations for tcp header
#include <netinet/ip.h>  // Provides declarations for ip header
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <strings.h>
#include <arpa/inet.h>

#include <unistd.h>
// #include <sys/time.h>
// #include <sys/types.h>


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

/*
    Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes)
{
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

void myHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */

	u_int size_ip;
	u_int size_tcp;

	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

    printf("%x\n", tcp->th_sport);
    if ((tcp->th_flags & TH_SYN) && (tcp->th_flags & TH_ACK))
        printf("port is open\n");
    if ((tcp->th_flags & TH_RST) && (tcp->th_flags & TH_ACK))
        printf("port is closed\n");
}

int main(int argc, char *argv[]) {
    int TMP_port[2] = {631, 80}; // TODO filter
    int TMP_port_len = 2;
    char TMP_dest_addr[] = "127.0.0.1"; // TODO
    char TMP_source_addr[] = "127.0.0.1"; // TODO

    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */

    struct sockaddr_in addr;
    int sock;

    if (42/* TODO if interface is not defined */) {
        /* Define the device */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            return(2);
        }
    }
    dev = "lo"; //TODO

    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    (void) mask;
    printf("iface:%s\n", dev);

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }


    //
    //
    //
    // SCAN
    //
    //
    //

    for (int i = 0; i < TMP_port_len; i++) {

        // SOCKET CREATION
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock == -1) {
            printf("Error opening socket\n");
            return -1;
        }

        //Datagram to represent the packet
        char datagram[4096] , source_ip[32] , *data , *pseudogram;

        //zero out the packet buffer
        memset (datagram, 0, 4096);

        //IP header
        struct iphdr *iph = (struct iphdr *) datagram;

        //TCP header
        struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
        struct sockaddr_in sin;
        struct pseudo_header psh;

        //Data part
        data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
        strcpy(data , "ABCDEFGHIJKLMNOPQRSTUVWXYZ");

        //some address resolution
        strcpy(source_ip , "127.0.0.1");
        sin.sin_family = AF_INET;
        sin.sin_port = htons(TMP_port[i]);
        sin.sin_addr.s_addr = inet_addr ("127.0.0.1");

        //Fill in the IP Header
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

        //Ip checksum
        iph->check = csum ((unsigned short *) datagram, iph->tot_len);

        //TCP Header
        tcph->source = htons (42);
        tcph->dest = htons (TMP_port[i]);
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

        //Now the TCP checksum
        psh.source_address = inet_addr( source_ip );
        psh.dest_address = sin.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data) );

        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
        pseudogram = malloc(psize);

        memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + strlen(data));

        tcph->check = csum( (unsigned short*) pseudogram , psize);

        //IP_HDRINCL to tell the kernel that headers are included in the packet
        int one = 1;
        const int *val = &one;

        /* Compile and apply the filter */
        char* filter_exp = malloc(sizeof(char) * 40);	/* The filter expression */
        sprintf(filter_exp, "tcp src port %d and tcp dst port 42", TMP_port[i]);
        printf("filter:%s\n", filter_exp);
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return(2);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return(2);
        }

        if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) {
            perror("Error setting IP_HDRINCL");
            exit(0);
        }

        //Send the packet
        if (sendto (sock, datagram, iph->tot_len , 0, (struct sockaddr *) &sin, sizeof (sin)) < 0) {
            perror("sendto failed");
        } else {
            printf ("Packet Send. Length : %d \n" , iph->tot_len);
        }

        // packet = pcap_next(handle, &header);
        pcap_loop(handle, 1, myHandler, NULL);
        // Grab packet

        /* Print its length */
		printf("Jacked a packet with length of [%d]\n", header.len);
		/* And close the session */
    }
    pcap_close(handle);
    //
    //
    //
    // SCAN
    //
    //
    //

    return(0);
}
