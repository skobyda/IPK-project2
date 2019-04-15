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

int main(int argc, char *argv[]) {
    int TMP_port[2] = {80, 20}; // TODO filter
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

    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    (void) mask;

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
        strcpy(source_ip , "192.168.1.2");
        sin.sin_family = AF_INET;
        sin.sin_port = htons(TMP_port[i]);
        sin.sin_addr.s_addr = inet_addr ("1.2.3.4");

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
        tcph->source = htons (1234);
        tcph->dest = htons (80);
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
        char filter_exp[11];	/* The filter expression */
        sprintf(filter_exp, "port %d", TMP_port[i]);
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return(2);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return(2);
        }

        if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
        {
            perror("Error setting IP_HDRINCL");
            exit(0);
        }

        //Send the packet
        if (sendto (sock, datagram, iph->tot_len , 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
        {
            perror("sendto failed");
        }
        //Data send successfully
        else
        {
            printf ("Packet Send. Length : %d \n" , iph->tot_len);
        }

        packet = pcap_next(handle, &header);

        /* Print its length */
		printf("Jacked a packet with length of [%d]\n", header.len);
		/* And close the session */
		pcap_close(handle);
		return(0);
    }
    //
    //
    //
    // SCAN
    //
    //
    //

    //
    // struct iphdr *
    // struct tcphdr *
    // struct sockaddr_in
    // TODO naplnit IP a TCP/IDP struktury
    // checksum
    //

    // TODO for each port
        // addr.sin_port = htons(PORT);
        // addr.sin_addr.s_addr = 0;
        // addr.sin_addr.s_addr = INADDR_ANY;
        // addr.sin_family = AF_INET;
        // if(bind(sock, (struct sockaddr *)&addr,sizeof(struct sockaddr_in) ) == -1) {
        // printf("Error binding socket\n");
        // return -1;
        // }

        // setsockopt()

        /* Compile and apply the filter */
        /* 
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return(2);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return(2);
        }


        sendto(sock, packet, packet_length, 0, sockaddr*, sizeof(sockaddr)); */
        //
        /* Grab a packet */
        // packet = pcap_next(handle, &header); // or pcap_loop ak timeout nefunguje
        /* Print its length */
        // printf("Jacked a packet with length of [%d]\n", header.len);
        /* And close the session */
        // pcap_close(handle);
    return(0);
}
