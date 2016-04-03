#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#define __FAVOR_BSD
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <bits/ioctls.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/ethernet.h>

#define ETH_SIZE	sizeof(struct ether_header)
#define IPH_SIZE	sizeof(struct ip)
#define TCP_SIZE	sizeof(struct tcphdr)
#define PSH_SIZE	sizeof(struct pseudo_hdr)

struct pseudo_hdr {
	unsigned long src;
	unsigned long dst;
	unsigned char zero;
	unsigned char protocol;
	unsigned short tcplen;
};

uint16_t checksum (uint16_t *addr, size_t len)
{
	uint64_t sum = 0;
	
	for (; len > 1; len -= 2)
		sum += *addr++;

	if (len > 0)
		sum += *(char *)addr;
		
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
		
	return ~sum;
}

int get_tcp_checksum (size_t pkt_len, struct ip ip, struct tcphdr tcp,
			const char *data, int data_len)
{

	size_t slen = pkt_len - (ip.ip_hl * 4) - ETH_SIZE;
	size_t hlen = PSH_SIZE + slen;
	unsigned char *sumblock = malloc(hlen);
	int ret;
	
	struct pseudo_hdr phdr;

	memset(&phdr, 0x00, PSH_SIZE);

	phdr.src 	= ip.ip_src.s_addr;
	phdr.dst 	= ip.ip_dst.s_addr;
	phdr.zero 	= 0;
	phdr.protocol 	= IPPROTO_TCP;
	phdr.tcplen 	= htons(slen);

	memcpy(sumblock, &phdr, PSH_SIZE);
	memcpy(sumblock + PSH_SIZE, &tcp, TCP_SIZE);
	memcpy(sumblock + PSH_SIZE + TCP_SIZE, data, data_len);

	ret = checksum((unsigned short *)sumblock, hlen);
	
	free(sumblock);
	
	return ret;
}

void build_eth_hdr (struct ether_header *eth, uint16_t type,
			uint8_t src[ETH_ALEN], uint8_t dst[ETH_ALEN])
{
	memset(eth, 0x00, ETH_SIZE);
	
	eth->ether_type = htons(type);

	memcpy(eth->ether_shost, src, ETH_ALEN);
	memcpy(eth->ether_dhost, dst, ETH_ALEN);
}

void build_ip_hdr (struct ip *ip, uint32_t len, 
			uint16_t flags, uint16_t id,
			const char *src, const char *dst)
{
	memset(ip, 0x00, IPH_SIZE);

	ip->ip_v 	= 0x4;
	ip->ip_hl 	= 0x5;
	ip->ip_tos 	= 0x0;
	ip->ip_id 	= htonl(id);
	ip->ip_off 	= htons(flags);
	ip->ip_len 	= htonl(len);
	ip->ip_ttl 	= 64;
	ip->ip_p 	= 0x6;
	
	inet_aton(src, &ip->ip_src);
	inet_aton(dst, &ip->ip_dst);

	ip->ip_sum = checksum((unsigned short *)ip, IPH_SIZE);
}

void build_tcp_hdr (struct tcphdr *tcp, size_t pkt_len,
			uint16_t sport, uint16_t dport,
			uint32_t seq, uint32_t ack,
			uint32_t flags, uint32_t win,
			const char *data, size_t data_len)
{
	memset(tcp, 0x00, TCP_SIZE);

	tcp->th_sport 	= htons(sport);
	tcp->th_dport 	= htons(dport);
	tcp->th_seq 	= htonl(seq);
	tcp->th_ack 	= htonl(ack);
	tcp->th_off 	= 0x5;
	tcp->th_x2 	= 0x0;
	tcp->th_flags 	= flags;
	tcp->th_win 	= htons(win);
	tcp->th_urp 	= 0x0;
}

int get_hwaddr_ifr (uint8_t dst[ETH_ALEN], const char *interface)
{
	int sd;
	struct ifreq ifr;

	if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
		return -1;
		
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));

	if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0)
		return -1;
		
	close(sd);

	memcpy(dst, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	
	return 0;
}

void get_hwaddr_str (uint8_t dst[ETH_ALEN], const char *src)
{
	memcpy(dst, ether_aton(src)->ether_addr_octet, ETH_ALEN);
}

int send_tcp_raw (const char *interface, uint8_t src_mac[ETH_ALEN], uint8_t dst_mac[ETH_ALEN],
			const char *src_ip, const char *dst_ip, uint16_t ip_flags,
			uint32_t tcp_flags, uint32_t seq, uint32_t ack, uint32_t win,
			uint16_t src_port, uint16_t dst_port,
			const char *data, size_t data_len)
{
	int sd, bytes;
	struct sockaddr_ll device;
	
	char *dst = calloc(1, IP_MAXPACKET);
	size_t iov_len = ETH_SIZE + IPH_SIZE + TCP_SIZE + data_len;

	struct ether_header eth;
	struct ip iph;
	struct tcphdr tcp;
	
	get_hwaddr_ifr(src_mac, interface);
	get_hwaddr_str(dst_mac, "FF:FF:FF:FF:FF:FF");

	build_eth_hdr(&eth, ETHERTYPE_IP, src_mac, dst_mac);
	build_ip_hdr(&iph, iov_len - ETH_SIZE, ip_flags, 0, src_ip, dst_ip);
	build_tcp_hdr(&tcp, iov_len, src_port, dst_port,
		      seq, ack, tcp_flags, win, data, data_len);
		      
	tcp.th_sum = get_tcp_checksum(iov_len, iph, tcp, data, data_len);
		      
	memcpy(dst, &eth, ETH_SIZE);
	memcpy(dst + ETH_SIZE, &iph, IPH_SIZE);
	memcpy(dst + ETH_SIZE + IPH_SIZE, &tcp, TCP_SIZE);
	if (data)
		memcpy(dst + ETH_SIZE + IPH_SIZE + TCP_SIZE, data, data_len);

	if ((device.sll_ifindex = if_nametoindex(interface)) == 0)
		return -1;

	device.sll_family = AF_PACKET;
	memcpy (device.sll_addr, src_mac, ETH_ALEN);
	device.sll_halen = htons(ETH_ALEN);

	if ((sd = socket(PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0)
		return -1;

	bytes = sendto(sd, dst, iov_len, 0, (struct sockaddr *)&device, sizeof(device));
	
	close(sd);
	free(dst);
	
	return bytes;
}

int main (void)
{
	int bytes;
	
	const char *data = "GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n";
	size_t data_len = strlen(data);

	const char *interface = "eth1";
	
	uint8_t src_mac[ETH_ALEN];
	uint8_t dst_mac[ETH_ALEN];
	
	const char *src_ip = "192.168.1.103";
	const char *dst_ip = "192.168.1.101";
	uint16_t ip_flags = IP_DF;

	uint32_t seq = 12;
	uint32_t ack = 12;
	uint32_t win = 65535;
	uint16_t src_port = 33345;
	uint16_t dst_port = 80;

	get_hwaddr_ifr(src_mac, interface);
	get_hwaddr_str(dst_mac, "FF:FF:FF:FF:FF:FF");
	
	bytes = send_tcp_raw(interface, src_mac, dst_mac,
			src_ip, dst_ip, ip_flags,
			TH_SYN, 1, 0, win,
			src_port, dst_port,
			NULL, 0);

	/*bytes = send_tcp_raw(interface, src_mac, dst_mac,
			src_ip, dst_ip, ip_flags,
			TH_PUSH|TH_ACK, seq, ack, win,
			src_port, dst_port,
			data, data_len);*/
	
	printf("Sent %d\n", bytes);
	
	return 0;
}
