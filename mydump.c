
//reference -> http://www.tcpdump.org/sniffex.c
//https://stackoverflow.com/questions/977684/how-can-i-express-10-milliseconds-using-timeval

/// mydump [-i interface] [-r file] [-s string] expression



#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <netinet/ether.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet header */
struct sniff_ethernet
{
    u_char ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip
{
    u_char ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char ip_ttl;                 /* time to live */
    u_char ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct in_addr ip_src, ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp
{
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};
// FIX ME :: chech ether header for ip
struct sniff_udp
{
    unsigned short int uh_sport;
    unsigned short int uh_dport;
    unsigned short int uh_len;
    unsigned short int uh_check;
};
int match_string_flag;
char *match_string;
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_time(struct timeval tv)
{

    struct tm *ptm;
    char time_string[40];
    long milliseconds;

    /* Obtain the time of day, and convert it to a tm struct. */
    ptm = localtime(&tv.tv_sec);
    /* Format the date and time, down to a single second. */
    strftime(time_string, sizeof(time_string), "%Y-%m-%d %H:%M:%S", ptm);
    /* Compute milliseconds from microseconds. */
    milliseconds = tv.tv_usec;
    /* Print the formatted time, in seconds, followed by a decimal point
      and the milliseconds. */
    printf("%s.%06ld", time_string, milliseconds);
}

void ether_ntoa_c(struct ether_addr *addr)
{
    printf( "%02X:%02X:%02X:%02X:%02X:%02X",
            addr->ether_addr_octet[0], addr->ether_addr_octet[1],
            addr->ether_addr_octet[2], addr->ether_addr_octet[3],
            addr->ether_addr_octet[4], addr->ether_addr_octet[5]);
}
/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

    int i;
    int gap;
    const u_char *ch;

//    /* offset */
//    printf("%05d   ", offset);

    /* hex */
    ch = payload;
    for (i = 0; i < len; i++)
    {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16)
    {
        gap = 16 - len;
        for (i = 0; i < gap; i++)
        {
            printf("   ");
        }
    }
    printf("   ");

    /* ascii (if printable) */
    ch = payload;
    for (i = 0; i < len; i++)
    {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");

    return;
}

void get_printable_string(char* string_to_process,int len,char* final_string)
{
    for (int i = 0; i < len; i++)
    {
        if (isprint(*string_to_process))
            *final_string = *string_to_process;
        else
            *final_string = '.';
        string_to_process++;
        final_string++;
    }
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

    int len_rem = len;
    int line_width = 16;            /* number of bytes per line */
    int line_len;
    int offset = 0;                    /* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width)
    {
        print_hex_ascii_line(ch, len, offset);
        printf("\n");
        return;
    }

    /* data spans multiple lines */
    for (;;)
    {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width)
        {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }
    printf("\n");

    return;
}

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    static int count = 0;                   /* packet counter */

    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    struct sniff_udp *udp;            /* The TCP header */
    const char *payload;                    /* Packet payload */

    int size_ip;
    int size_tcp;
    int size_udp;
    int size_payload;
    int match_flag;
    char *string;
    count++;
    ethernet = (struct sniff_ethernet *) (packet);
    ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    char *protocol;
    if (ntohs(ethernet->ether_type) == 0x800)
    {
        if (size_ip < 20)
        {
            printf("   * Invalid IP header length: %u bytes\n", size_ip);
            return;
        }

        switch (ip->ip_p)
        {
            case IPPROTO_TCP:
            {
                match_flag =0;
                tcp = (struct sniff_tcp *) (packet + SIZE_ETHERNET + size_ip);
                size_tcp = TH_OFF(tcp) * 4;
                if (size_tcp < 20)
                {
                    printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                    return;
                }
                payload = (u_char * )(packet + SIZE_ETHERNET + size_ip + size_tcp);
                size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
                match_flag = 0;
                if (match_string_flag)
                {
                    char *tmp_payload = (char *) malloc(sizeof(char) * size_payload);
                    get_printable_string((char *) payload, size_payload, tmp_payload);
                    string = strstr(tmp_payload, match_string);
                    if (string)
                    {
                        match_flag = 1;
                    }
                }
                else
                {
                    match_flag = 1;
                }

                if ((size_payload > 0) && match_flag)
                {
                    print_time(header->ts);
                    printf(" ");
                    ether_ntoa_c((struct ether_addr *) ethernet->ether_shost);
                    printf(" -> ");
                    ether_ntoa_c((struct ether_addr *) ethernet->ether_dhost);
//                    printf(" %s", ether_ntoa((struct ether_addr *) ethernet->ether_shost));
//                    printf("-> %s", ether_ntoa((struct ether_addr *) ethernet->ether_dhost));
                    printf(" type 0x%04X", ntohs(ethernet->ether_type));
                    printf(" len %d\n", header->caplen);
                    printf("%s:%d ->", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
                    printf(" %s:%d TCP\n", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
                    print_payload(payload, size_payload);
                }
                break;
            }

            case IPPROTO_UDP:
            {
                match_flag =0;
                udp = (struct sniff_udp *) (packet + SIZE_ETHERNET + size_ip);
                size_udp = 8;



                /* define/compute tcp payload (segment) offset */
                payload = (u_char * )(packet + SIZE_ETHERNET + size_ip + size_udp);

                /* compute tcp payload (segment) size */
                size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);

                if (match_string_flag)
                {
                    char *tmp_payload = (char *) malloc(sizeof(char) * size_payload);
                    get_printable_string((char *) payload, size_payload, tmp_payload);
                    string = strstr(tmp_payload, match_string);
                    if (string)
                    {
                        match_flag = 1;
                    }
                }
                else
                {
                    match_flag = 1;
                }
                if (size_payload > 0 && match_flag)
                {
                    print_time(header->ts);
                    printf(" ");
                    ether_ntoa_c((struct ether_addr *) ethernet->ether_shost);
                    printf(" -> ");
                    ether_ntoa_c((struct ether_addr *) ethernet->ether_dhost);
                    printf(" type 0x%04X", ntohs(ethernet->ether_type));
                    printf(" len %d\n", header->caplen);
                    printf("%s:%d ->", inet_ntoa(ip->ip_src), ntohs(udp->uh_sport));
                    printf(" %s:%d UDP\n", inet_ntoa(ip->ip_dst), ntohs(udp->uh_dport));
                    print_payload(payload, size_payload);
                }
                break;
            }
            case IPPROTO_ICMP:
            {
                match_flag =0;
                payload = (u_char * )(packet + SIZE_ETHERNET + size_ip);
                size_payload = ntohs(ip->ip_len) - (size_ip);
                if (match_string_flag)
                {
                    char *tmp_payload = (char *) malloc(sizeof(char) * size_payload);
                    get_printable_string((char *) payload, size_payload, tmp_payload);
                    string = strstr(tmp_payload, match_string);
                    if (string)
                    {
                        match_flag = 1;
                    }
                }
                else
                {
                    match_flag = 1;
                }

                if (size_payload > 0 && match_flag)
                {
                    print_time(header->ts);
                    printf(" ");
                    ether_ntoa_c((struct ether_addr *) ethernet->ether_shost);
                    printf(" -> ");
                    ether_ntoa_c((struct ether_addr *) ethernet->ether_dhost);
                    printf(" type 0x%04X", ntohs(ethernet->ether_type));
                    printf(" len %d\n", header->caplen);
                    printf("%s ->", inet_ntoa(ip->ip_src));
                    printf(" %s ICMP\n", inet_ntoa(ip->ip_dst));
                    print_payload(payload, size_payload);
                }
                break;
            }
            default:
            {
                match_flag =0;
                payload = (u_char * )(packet + SIZE_ETHERNET + size_ip);
                size_payload = ntohs(ip->ip_len) - (size_ip);
                if (match_string_flag)
                {
                    char *tmp_payload = (char *) malloc(sizeof(char) * size_payload);
                    get_printable_string((char *) payload, size_payload, tmp_payload);
                    string = strstr(match_string,tmp_payload);
                    if (string)
                    {
                        match_flag = 1;
                    }
                }
                else
                {
                    match_flag = 1;
                }
                if (size_payload > 0 && match_flag)
                {
                    print_time(header->ts);
                    printf(" ");
                    ether_ntoa_c((struct ether_addr *) ethernet->ether_shost);
                    printf(" -> ");
                    ether_ntoa_c((struct ether_addr *) ethernet->ether_dhost);
                    printf(" type 0x%04X", ntohs(ethernet->ether_type));
                    printf(" len %d\n", header->caplen);
                    printf("%s ->", inet_ntoa(ip->ip_src));
                    printf(" %s \n", inet_ntoa(ip->ip_dst));
                    print_payload(payload, size_payload);
                }
                break;
            }
        }
        return;
    }
    else
    {
        match_flag =0;
        payload = (u_char * )(packet + SIZE_ETHERNET);
        size_payload = header->len - (SIZE_ETHERNET);
        if (match_string_flag)
        {
            char *tmp_payload = (char *) malloc(sizeof(char) * size_payload);
            get_printable_string((char *) payload, size_payload, tmp_payload);
            string = strstr(tmp_payload, match_string);
            if (string)
            {
                match_flag = 1;
            }
        }
        else
        {
            match_flag = 1;
        }
        if (size_payload > 0 && match_flag)
        {
            print_time(header->ts);
            printf(" ");
            ether_ntoa_c((struct ether_addr *) ethernet->ether_shost);
            printf(" -> ");
            ether_ntoa_c((struct ether_addr *) ethernet->ether_dhost);
            printf(" type 0x%04X", ntohs(ethernet->ether_type));
            printf(" len %d\n", header->caplen);
            print_payload(payload, size_payload);
        }
    }
}

int
main(int argc, char **argv)
{

    char *dev = NULL;
    char *fname;
    int i, capture_mode = 0;
    char filter_exp[2048];        /* filter expression [3] */
    struct bpf_program fp;            /* compiled filter program (expression) */
    char errbuf[PCAP_ERRBUF_SIZE];        /* error buffer */
    pcap_t *handle;                /* packet capture handle */
    bpf_u_int32 mask;            /* subnet mask */
    bpf_u_int32 net;            /* ip */
    int num_packets = -1;            /* number of packets to capture */
    int indicator = 2;
    int interface_flag =0;

    int opt;
    while ((opt = getopt(argc, argv, "i:r:s:p")) != -1)
    {
        switch (opt)
        {
            case 'i':
            {
                dev = optarg;
                interface_flag =1;
                break;
            }
            case 'r':
            {
                fname = optarg;
                capture_mode = 1;
                break;
            }
            case 's':
            {
                match_string = optarg;
                match_string_flag = 1;
                break;
            }
            case '?':
            {
                printf("no argument passed for-%c \n", optopt);
                return 0;

            }
        }
    }
    int match_string_index = 0;
    for (int argv_index = optind; argv_index < argc; argv_index++)
    {
        strcat(filter_exp,argv[argv_index]);
        strcat(filter_exp," ");
    }
    if(interface_flag ==0)
    {
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL)
        {
            fprintf(stderr, "Couldn't find default device: %s\n",
                    errbuf);
            exit(EXIT_FAILURE);
        }
    }

    /* print capture info */
    printf("Interface: %s\n", dev);
    printf("Mode: %s\n", capture_mode == 0 ? "from interface" : "from file");
    printf("Number of packets: %d\n", num_packets);
    printf("Match String : %s\n", match_string);
    printf("BPF String : %s\n", filter_exp);
    //open file or device
    if (capture_mode == 0)
    {

        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
        {
            fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                    dev, errbuf);
            net = 0;
            mask = 0;
        }
        handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
        if (handle == NULL)
        {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        handle = pcap_open_offline(fname, errbuf);
        if (handle == NULL)
        {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            exit(EXIT_FAILURE);
        }

    }


    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* now we can set our callback function */
    pcap_loop(handle, num_packets, got_packet, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    printf("\nCapture complete.\n");

    return 0;
}