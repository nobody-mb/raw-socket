#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN	6

struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
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

#define X86_SUPPORT

int print_num_padded (unsigned char *dst, int src, int base, int pad)
{
#ifdef X86_SUPPORT
	asm volatile (
			"movq %%rdi, %%rsi\n"	/* ptr = dst */
			"addq %%rcx, %%rsi\n"
		"pnp_loop1:\n"
			"cmpq $0, %%rax\n"	/* src == 0 */
			"jle pnp_loop2\n"
			"decq %%rsi\n"
			"cmpq %%rsi, %%rdi\n"	/* ptr, dst */
			"jg pnp_loop2\n"
			"xorq %%rdx, %%rdx\n"
			"idivq %%rbx\n"		/* tmp = rdx, src = rax */
			"cmpb $9, %%dl\n"
			"jg pnp_hexval\n"
			"addb $0x30, %%dl\n"	/* '0' */
			"jmp pnp_append\n"
		"pnp_hexval:\n"
			"addb $0x57, %%dl\n"	/* 'a' - 10 */
		"pnp_append:\n"
			"movb %%dl, (%%rsi)\n"
			"jmp pnp_loop1\n"
		"pnp_loop2:\n"
			"decq %%rsi\n"
			"cmpq %%rsi, %%rdi\n"
			"jg pnp_endl2\n"
			"movb $0x30, (%%rsi)\n"	/* '0' */
			"jmp pnp_loop2\n"
		"pnp_endl2:\n"
	
		: : "D" (dst),
		"b" (base),
		"c" (pad), 
		"a" (src)
		: "rdx");
#else
	unsigned char *ptr = dst;
	unsigned char tmp, add;
	
	for (ptr += pad; src && --ptr >= dst; src /= base) {
		tmp = src % base;
		add = (tmp <= 9) ? ('0') : ('a' - 10);
		*ptr = tmp + add;
	}	
	
	while (--ptr >= dst)
		*ptr = '0';
#endif

	return pad;
}

void print_line (const unsigned char *src, int len, int offset)
{
	int i;
	unsigned char buf[128];
	unsigned char *bptr = (unsigned char *)buf;
	
	memset(buf, 0, sizeof(buf));
	
	bptr += print_num_padded(bptr, offset, 10, 5);
	*bptr++ = ' ', *bptr++ = ' ';

	for (i = 0; i < len; i++) {
		bptr += print_num_padded(bptr, src[i], 16, 2);
		if (i == 7) *bptr++ = ' ';
		*bptr++ = ' ';
	}

	i = 3;
	if (len < 8)	i++;
	if (len < 16)	i += ((16 - len) * 3);

	while (i--)
		*bptr++ = ' ';

	for (i = 0; i < len; i++)
		*bptr++ = (isprint(src[i]) ? src[i] : '.');

	puts((const char *)buf);
}

void print_payload (const unsigned char *src, int len, int line_width)
{
	int line_len, off = 0;

	while (len > line_width) {
		line_len = line_width % len;
		print_line(src, line_len, off);
		len -= line_len;
		src += line_len;
		off += line_width;
	}
	
	if (len > 0)
		print_line(src, len, off);
}


/* everything below this line falls under this copyright: 
 * This software is a modification of Tim Carstens' "sniffer.c"
 * demonstration source code, released as follows:
 * 
 * sniffer.c
 * Copyright (c) 2002 Tim Carstens
 * 2002-01-07
 * Demonstration of using libpcap
 * timcarst -at- yahoo -dot- com
 */

void got_packet (u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static int count = 1;

	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
	const unsigned char *payload;

	int size_ip;
	int size_tcp;
	int size_payload;
	
	printf("\nPacket number %d:\n", count++);

	ethernet = (struct sniff_ethernet *)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;
	
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));
	
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}
	
	/*
	 *  OK, this packet is TCP.
	 */
	
	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	
	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) {
		printf("   Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload, 16);
	}

	return;
}

int main (int argc, char **argv)
{
	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "ip";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 100;			/* number of packets to capture */

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n",
		    errbuf);
		exit(EXIT_FAILURE);
	}
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
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

