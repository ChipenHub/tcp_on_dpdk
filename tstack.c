#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_ether.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#define ENABLE_ARP					1
#define ENABLE_ICMP					1
#define ENABLE_ARP_REPLY			1
#define ENABLE_DEBUG				1
#define ENABLE_TIMER				1
#define ENABLE_RINGBUFFER			1
#define ENABLE_MULTITHREAD			1
#define ENABLE_UDP_APP				1
#define ENABLE_TCP_APP				1

#define RING_SIZE					1024
#define NUM_MBUFS					8191
#define MBUF_CACHE_SIZE				250
#define RX_RING_SIZE				1024
#define TX_RING_SIZE				1024
#define PKT_BURST					32
#define BURST_SIZE					32
#define TCP_OPTIONAL_LENGTH			10
#define TCP_MAX_SEQ					4294967295U
#define TCP_RX_WIN					14600

#define UDP_APP_RECV_BUFFER_SIZE	128
#define TIMER_RESOLUTION_CYCLES		180000000000ULL

#define MAKE_IPV4_ADDR(a, b, c, d)	(a + (b<<8) + (c<<16) + (d<<24))

/* Global variables */
static uint32_t g_local_ip = MAKE_IPV4_ADDR(192, 168, 0, 120);
static uint16_t g_dpdk_port_id = 0;
static uint8_t g_src_mac[RTE_ETHER_ADDR_LEN];
static uint8_t g_dst_mac[RTE_ETHER_ADDR_LEN];
static uint32_t g_src_ip;
static uint32_t g_dst_ip;
static uint16_t g_src_port;
static uint16_t g_dst_port;
static struct rte_mempool *g_mbuf_pool = NULL;

#if ENABLE_TCP_APP
typedef enum tcp_status {
	TCP_STATUS_CLOSED = 0,
	TCP_STATUS_LISTEN,
	TCP_STATUS_SYN_RCVD,
	TCP_STATUS_SYN_SENT,
	TCP_STATUS_ESTABLISHED,
	TCP_STATUS_FIN_WAIT_1,
	TCP_STATUS_FIN_WAIT_2,
	TCP_STATUS_CLOSING,
	TCP_STATUS_TIME_WAIT,
	TCP_STATUS_CLOSE_WAIT,
	TCP_STATUS_LAST_ACK
} tcp_status_t;

struct tcp_stream {
	int fd;
	uint32_t dip;
	uint8_t localmac[RTE_ETHER_ADDR_LEN];
	uint16_t dport;
	uint16_t proto;
	uint32_t sip;
	uint16_t sport;
	
	struct rte_ring *sndbuf;
	struct rte_ring *rcvbuf;
	
	struct tcp_stream *prev;
	struct tcp_stream *next;
	
	tcp_status_t status;
	uint32_t snd_nxt;  /* sequence number */
	uint32_t rcv_nxt;  /* acknowledgment number */
};

struct tcp_fragment {
	rte_be16_t sport;
	rte_be16_t dport;
	rte_be32_t sent_seq;
	rte_be32_t recv_ack;
	uint8_t data_off;
	uint8_t tcp_flags;
	rte_be16_t rx_win;
	rte_be16_t cksum;
	rte_be16_t tcp_urp;
	
	int optlen;
	uint32_t option[TCP_OPTIONAL_LENGTH];
	
	unsigned char *data;
	int length;
};

struct tcp_table {
	int count;
	struct tcp_stream *tcp_set;
};
#endif

struct localhost {
	int fd;
	uint32_t localip;
	uint8_t localmac[RTE_ETHER_ADDR_LEN];
	uint16_t localport;
	int protocol;
	struct rte_ring *sndbuf;
	struct rte_ring *rcvbuf;
	struct localhost *prev;
	struct localhost *next;
	pthread_cond_t cond;
	pthread_mutex_t mutex;
};

#define DEFAULT_FD_NUM	3
static struct localhost *g_lhost = NULL;

#if ENABLE_ARP_REPLY
#include "arp.h"
static uint8_t g_default_arp_mac[RTE_ETHER_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
#endif

#if ENABLE_RINGBUFFER
struct inout_ring {
	struct rte_ring *in;
	struct rte_ring *out;
};

static struct inout_ring *g_ring_inst = NULL;

struct inout_ring *ring_instance(void) 
{
	if (g_ring_inst == NULL) {
		g_ring_inst = rte_malloc("in/out ring", sizeof(struct inout_ring), 0);
		if (g_ring_inst == NULL) {
			rte_exit(EXIT_FAILURE, "Failed to allocate ring instance\n");
		}
		memset(g_ring_inst, 0, sizeof(struct inout_ring));
	}
	return g_ring_inst;
}
#endif

/* Utility functions */
static uint16_t 
checksum(uint16_t *addr, int count) 
{
	register long sum = 0;

	while (count > 1) {
		sum += *(unsigned short*)addr++;
		count -= 2;
	}

	if (count > 0) {
		sum += *(unsigned char *)addr;
	}

	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return ~sum;
}

#if ENABLE_UDP_APP
static int g_fd_counter = DEFAULT_FD_NUM;

int get_fd_from_bitmap(void) 
{
	return ++g_fd_counter;
}

void *get_hostinfo_from_fd(int sockfd) 
{
	struct localhost *host;
	for (host = g_lhost; host != NULL; host = host->next) {
		if (sockfd == host->fd)
			return host;
	}

#if ENABLE_TCP_APP
	struct tcp_table *table = tcp_instance();
	if (table != NULL) {
		struct tcp_stream *iter;
		for (iter = table->tcp_set; iter != NULL; iter = iter->next) {
			if (sockfd == iter->fd) {
				return iter;
			}
		}
	}
#endif
	return NULL;
}

struct localhost *get_hostinfo_from_ipport(uint32_t dip, uint16_t port, uint8_t proto) 
{
	struct localhost *host;
	for (host = g_lhost; host != NULL; host = host->next) {
		if (dip == host->localip &&
			port == host->localport &&
			proto == host->protocol) {
			return host;
		}
	}
	return NULL;
}
#endif

/* Initialize network port */
static int 
init_port(uint16_t port_id) 
{
	struct rte_eth_conf port_conf = {0};
	struct rte_eth_dev_info dev_info;
	int ret;

	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret != 0) {
		printf("Error: Failed to get device info for port %u\n", port_id);
		return ret;
	}

	ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
	if (ret != 0) {
		printf("Error: Failed to configure port %u\n", port_id);
		return ret;
	}

	ret = rte_eth_rx_queue_setup(port_id, 0, RX_RING_SIZE, 
								rte_eth_dev_socket_id(port_id), NULL, g_mbuf_pool);
	if (ret < 0) {
		printf("Error: Failed to setup RX queue for port %u\n", port_id);
		return ret;
	}

	ret = rte_eth_tx_queue_setup(port_id, 0, TX_RING_SIZE, 
								rte_eth_dev_socket_id(port_id), NULL);
	if (ret < 0) {
		printf("Error: Failed to setup TX queue for port %u\n", port_id);
		return ret;
	}

	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		printf("Error: Failed to start port %u\n", port_id);
		return ret;
	}

	rte_eth_promiscuous_enable(port_id);
	printf("Port %u initialized, promiscuous mode enabled\n", port_id);

	rte_eth_macaddr_get(port_id, (struct rte_ether_addr *)g_src_mac);
	printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		   g_src_mac[0], g_src_mac[1], g_src_mac[2], 
		   g_src_mac[3], g_src_mac[4], g_src_mac[5]);

	return 0;
}

#if ENABLE_ARP
struct rte_mbuf* 
encode_arp_pktmbuf(struct rte_mempool *mbuf_pool, uint16_t opcode, 
				   uint8_t *dst_mac, uint32_t sip, uint32_t dip) 
{
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		printf("Error: Failed to allocate mbuf for ARP packet\n");
		return NULL;
	}

	const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
	mbuf->pkt_len = total_length;
	mbuf->data_len = total_length;

	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);

	/* Ethernet header */
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt_data;
	rte_memcpy(eth->src_addr.addr_bytes, g_src_mac, RTE_ETHER_ADDR_LEN);

	if (dst_mac == NULL || !memcmp(dst_mac, g_default_arp_mac, RTE_ETHER_ADDR_LEN)) {
		memset(eth->dst_addr.addr_bytes, 0xFF, RTE_ETHER_ADDR_LEN);
	} else {
		rte_memcpy(eth->dst_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	}

	eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

	/* ARP header */
	struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
	arp->arp_hardware = htons(1);
	arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
	arp->arp_hlen = RTE_ETHER_ADDR_LEN;
	arp->arp_plen = sizeof(uint32_t);
	arp->arp_opcode = htons(opcode);

	rte_memcpy(arp->arp_data.arp_sha.addr_bytes, g_src_mac, RTE_ETHER_ADDR_LEN);
	
	if (dst_mac == NULL) {
		memset(arp->arp_data.arp_tha.addr_bytes, 0x00, RTE_ETHER_ADDR_LEN);
	} else {
		rte_memcpy(arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	}

	arp->arp_data.arp_sip = sip;
	arp->arp_data.arp_tip = dip;

	return mbuf;
}
#endif

#if ENABLE_ICMP
struct rte_mbuf *
encode_icmp_pktbuf(struct rte_mempool *mbuf_pool, uint8_t *dst_mac,
				   uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb) 
{
	const unsigned total_length = sizeof(struct rte_ether_hdr) + 
								  sizeof(struct rte_ipv4_hdr) + 
								  sizeof(struct rte_icmp_hdr);

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		printf("Error: Failed to allocate mbuf for ICMP packet\n");
		return NULL;
	}

	mbuf->pkt_len = total_length;
	mbuf->data_len = total_length;

	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);

	/* Ethernet header */
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt_data;
	rte_memcpy(eth->src_addr.addr_bytes, g_src_mac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->dst_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	/* IP header */
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(pkt_data + sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64;
	ip->next_proto_id = IPPROTO_ICMP;
	ip->src_addr = sip;
	ip->dst_addr = dip;
	
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	/* ICMP header */
	struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(pkt_data + sizeof(struct rte_ether_hdr) + 
														sizeof(struct rte_ipv4_hdr));
	icmp->icmp_type = 0;
	icmp->icmp_code = 0;
	icmp->icmp_ident = id;
	icmp->icmp_seq_nb = seqnb;

	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = checksum((uint16_t*)icmp, sizeof(struct rte_icmp_hdr));

	return mbuf;
}
#endif

static inline void
print_ether_addr(const char *name, const struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}

#if ENABLE_TIMER
static void
arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim, void *arg) 
{
	struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
	struct inout_ring *ring = ring_instance();
	
	if (mbuf_pool == NULL) {
		printf("Error: mbuf_pool is NULL in timer callback\n");
		return;
	}

	for (int i = 1; i < 255; i++) {
		uint32_t dstip = (g_local_ip & 0x00FFFFFF) | (0xFF000000 & (i << 24));
		uint8_t *dstmac = get_dst_macaddr(dstip);

		struct rte_mbuf *arp_buf = encode_arp_pktmbuf(mbuf_pool, RTE_ARP_OP_REQUEST, 
													  dstmac, g_local_ip, dstip);
		if (arp_buf != NULL) {
			int nb_tx = rte_ring_mp_enqueue_burst(ring->out, (void **)&arp_buf, 1, NULL);
			if (nb_tx != 1) {
				struct in_addr addr;
				addr.s_addr = dstip;
				printf("Failed to send ARP request for IP %s\n", inet_ntoa(addr));
				rte_pktmbuf_free(arp_buf);
			}
		}
	}
}
#endif

#if ENABLE_MULTITHREAD

#if ENABLE_UDP_APP
struct offload {
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;
	int protocol;
	unsigned char *data;
	uint16_t length;
};

static int
udp_process(struct rte_mbuf *mbuf) 
{
	struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(ehdr + 1);
	struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
	
	struct localhost *host = get_hostinfo_from_ipport(ip_hdr->dst_addr, 
													  udp_hdr->dst_port, 
													  ip_hdr->next_proto_id);
	if (host == NULL) {
		printf("No matching host found for UDP packet\n");
		rte_pktmbuf_free(mbuf);
		return -3;
	}

	struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
	if (ol == NULL) {
		printf("Failed to allocate offload structure\n");
		rte_pktmbuf_free(mbuf);
		return -1;
	}

	ol->sip = ip_hdr->src_addr;
	ol->sport = udp_hdr->src_port;
	ol->dip = ip_hdr->dst_addr; 
	ol->dport = udp_hdr->dst_port;
	ol->protocol = IPPROTO_UDP;
	ol->length = ntohs(udp_hdr->dgram_len) - sizeof(struct rte_udp_hdr);

	if (ol->length > 0) {
		ol->data = rte_malloc("udp_data", ol->length, 0);
		if (ol->data == NULL) {
			printf("Failed to allocate data buffer\n");
			rte_pktmbuf_free(mbuf);
			rte_free(ol);
			return -2;
		}
		rte_memcpy(ol->data, (unsigned char *)(udp_hdr + 1), ol->length);
	} else {
		ol->data = NULL;
	}

	int ret = rte_ring_mp_enqueue(host->rcvbuf, ol);
	if (ret != 0) {
		printf("Failed to enqueue UDP packet to receive buffer\n");
		if (ol->data) rte_free(ol->data);
		rte_free(ol);
		rte_pktmbuf_free(mbuf);
		return -4;
	}

	pthread_mutex_lock(&host->mutex);
	pthread_cond_signal(&host->cond);
	pthread_mutex_unlock(&host->mutex);
	
	rte_pktmbuf_free(mbuf);
	return 0;
}
#endif

#if ENABLE_TCP_APP
static struct tcp_table *g_tcp_inst = NULL;

static struct tcp_table *
tcp_instance(void) 
{
	if (g_tcp_inst == NULL) {
		g_tcp_inst = rte_malloc("tcp_table", sizeof(struct tcp_table), 0);
		if (g_tcp_inst == NULL) {
			rte_exit(EXIT_FAILURE, "Failed to allocate TCP table\n");
		}
		memset(g_tcp_inst, 0, sizeof(struct tcp_table));
	}
	return g_tcp_inst;	
}

static struct tcp_stream*
tcp_stream_search(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) 
{
	struct tcp_table *table = tcp_instance();
	struct tcp_stream *iter;

	/* First try exact match */
	for (iter = table->tcp_set; iter != NULL; iter = iter->next) {
		if (iter->dip == dip && iter->sip == sip && 
			iter->dport == dport && iter->sport == sport) {
			return iter;
		}
	}

	/* Then try listening socket match */
	for (iter = table->tcp_set; iter != NULL; iter = iter->next) {
		if (iter->dport == dport && iter->status == TCP_STATUS_LISTEN) {
			return iter;
		}
	}
	
	return NULL;
}

static struct tcp_stream*
tcp_stream_create(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) 
{
	struct tcp_table *table = tcp_instance();
	
	struct tcp_stream *stream = rte_malloc("tcp_stream", sizeof(struct tcp_stream), 0);
	if (stream == NULL) {
		printf("Failed to allocate TCP stream\n");
		return NULL;
	}
	
	memset(stream, 0, sizeof(struct tcp_stream));
	
	stream->dip = dip;
	stream->sip = sip;
	stream->dport = dport;
	stream->sport = sport;
	stream->fd = get_fd_from_bitmap();
	stream->proto = IPPROTO_TCP;
	stream->status = TCP_STATUS_LISTEN;

	/* Create rings with unique names */
	char ring_name[64];
	snprintf(ring_name, sizeof(ring_name), "TCP_SNDBUF_%d_%u", stream->fd, (unsigned)time(NULL));
	stream->sndbuf = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(), 0);
	if (stream->sndbuf == NULL) {
		printf("Failed to create TCP send buffer\n");
		rte_free(stream);
		return NULL;
	}

	snprintf(ring_name, sizeof(ring_name), "TCP_RCVBUF_%d_%u", stream->fd, (unsigned)time(NULL));
	stream->rcvbuf = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(), 0);
	if (stream->rcvbuf == NULL) {
		printf("Failed to create TCP receive buffer\n");
		rte_ring_free(stream->sndbuf);
		rte_free(stream);
		return NULL;
	}

	uint32_t next_seed = time(NULL);
	stream->snd_nxt = rand_r(&next_seed) % TCP_MAX_SEQ;
	stream->rcv_nxt = 0;

	rte_memcpy(stream->localmac, g_src_mac, RTE_ETHER_ADDR_LEN);
	
	/* Add to linked list */
	LL_ADD(stream, table->tcp_set);
	table->count++;
	
	return stream;
}

static int
tcp_handle_listen(struct tcp_stream *stream, struct rte_tcp_hdr *tcp_hdr, 
				  struct rte_ipv4_hdr *ip_hdr) 
{
	if (tcp_hdr->tcp_flags & RTE_TCP_SYN_FLAG) {
		if (stream->status == TCP_STATUS_LISTEN) {
			printf("TCP LISTEN: Received SYN, sending SYN+ACK\n");
			
			struct tcp_fragment *fragment = rte_malloc("tcp_fragment", 
													   sizeof(struct tcp_fragment), 0);
			if (fragment == NULL) {
				printf("Failed to allocate TCP fragment\n");
				return -1;
			}

			memset(fragment, 0, sizeof(struct tcp_fragment));
			
			fragment->sport = tcp_hdr->dst_port;
			fragment->dport = tcp_hdr->src_port;
			fragment->sent_seq = htonl(stream->snd_nxt);
			fragment->recv_ack = htonl(ntohl(tcp_hdr->sent_seq) + 1);
			
			/* Update receive sequence number */
			stream->rcv_nxt = ntohl(tcp_hdr->sent_seq) + 1;

			fragment->tcp_flags = (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG);
			fragment->rx_win = htons(TCP_RX_WIN);
			fragment->data_off = 0x50;
			fragment->data = NULL;
			fragment->length = 0;
			fragment->optlen = 0;

			int ret = rte_ring_mp_enqueue(stream->sndbuf, fragment);
			if (ret != 0) {
				printf("Failed to enqueue SYN+ACK fragment\n");
				rte_free(fragment);
				return -1;
			}
			
			stream->status = TCP_STATUS_SYN_RCVD;
			printf("TCP: Status changed to SYN_RCVD\n");
		}
	}
	return 0;
}

static int
tcp_handle_syn_rcvd(struct tcp_stream *stream, struct rte_tcp_hdr *tcp_hdr) 
{
	if (tcp_hdr->tcp_flags & RTE_TCP_ACK_FLAG) {
		if (stream->status == TCP_STATUS_SYN_RCVD) {
			uint32_t ack_num = ntohl(tcp_hdr->recv_ack);
			if (ack_num == stream->snd_nxt + 1) {
				printf("TCP SYN_RCVD: Received final ACK, connection established\n");
				
				/* Update send sequence number */
				stream->snd_nxt++;
				stream->status = TCP_STATUS_ESTABLISHED;
				
				printf("TCP: Status changed to ESTABLISHED\n");
			}
		}
	}
	return 0;
}

static int
tcp_handle_established(struct tcp_stream *stream, struct rte_tcp_hdr *tcp_hdr, int tcplen)
{
	/* Parse sequence numbers and payload length */
	uint32_t seg_seq = ntohl(tcp_hdr->sent_seq);
	uint8_t hdr_len = (tcp_hdr->data_off >> 4) * 4;
	int payload_len = tcplen - hdr_len;

	/* Drop out-of-order packets or send duplicate ACK */
	if (seg_seq != stream->rcv_nxt) {
		struct tcp_fragment *dup_ack = rte_malloc("tcp_dup_ack", 
												  sizeof(struct tcp_fragment), 0);
		if (dup_ack == NULL) {
			printf("Failed to allocate duplicate ACK\n");
			return -1;
		}
		
		memset(dup_ack, 0, sizeof(struct tcp_fragment));
		dup_ack->sport = tcp_hdr->dst_port;
		dup_ack->dport = tcp_hdr->src_port;
		dup_ack->sent_seq = htonl(stream->snd_nxt);
		dup_ack->recv_ack = htonl(stream->rcv_nxt);
		dup_ack->tcp_flags = RTE_TCP_ACK_FLAG;
		dup_ack->rx_win = htons(TCP_RX_WIN);
		dup_ack->data_off = 0x50;
		
		int ret = rte_ring_mp_enqueue(stream->sndbuf, dup_ack);
		if (ret != 0) {
			printf("Failed to enqueue duplicate ACK\n");
			rte_free(dup_ack);
		}
		return 0;
	}

	/* Process payload if present */
	if (payload_len > 0) {
		unsigned char *payload = (unsigned char*)tcp_hdr + hdr_len;
		
		struct tcp_fragment *rfrag = rte_malloc("tcp_recv_frag", 
												sizeof(struct tcp_fragment), 0);
		if (rfrag == NULL) {
			printf("Failed to allocate receive fragment\n");
			return -1;
		}
		
		memset(rfrag, 0, sizeof(struct tcp_fragment));
		rfrag->sport = tcp_hdr->dst_port;
		rfrag->dport = tcp_hdr->src_port;
		rfrag->sent_seq = htonl(stream->snd_nxt);
		rfrag->recv_ack = htonl(stream->rcv_nxt + payload_len);
		rfrag->tcp_flags = RTE_TCP_PSH_FLAG;
		rfrag->rx_win = htons(TCP_RX_WIN);
		rfrag->data_off = 0x50;
		rfrag->length = payload_len;
		
		rfrag->data = rte_malloc("tcp_payload", payload_len, 0);
		if (rfrag->data == NULL) {
			printf("Failed to allocate payload buffer\n");
			rte_free(rfrag);
			return -1;
		}
		
		rte_memcpy(rfrag->data, payload, payload_len);
		
		int ret = rte_ring_mp_enqueue(stream->rcvbuf, rfrag);
		if (ret != 0) {
			printf("Failed to enqueue receive fragment\n");
			rte_free(rfrag->data);
			rte_free(rfrag);
			return -1;
		}

		/* Update receive sequence number */
		stream->rcv_nxt += payload_len;
	}

	/* Send ACK */
	struct tcp_fragment *ack = rte_malloc("tcp_ack", sizeof(struct tcp_fragment), 0);
	if (ack == NULL) {
		printf("Failed to allocate ACK fragment\n");
		return -1;
	}
	
	memset(ack, 0, sizeof(struct tcp_fragment));
	ack->sport = tcp_hdr->dst_port;
	ack->dport = tcp_hdr->src_port;
	ack->sent_seq = htonl(stream->snd_nxt);
	ack->recv_ack = htonl(stream->rcv_nxt);
	ack->tcp_flags = RTE_TCP_ACK_FLAG;
	ack->rx_win = htons(TCP_RX_WIN);
	ack->data_off = 0x50;
	
	int ret = rte_ring_mp_enqueue(stream->sndbuf, ack);
	if (ret != 0) {
		printf("Failed to enqueue ACK\n");
		rte_free(ack);
		return -1;
	}

	/* Echo back data if present */
	if (payload_len > 0) {
		struct tcp_fragment *echo = rte_malloc("tcp_echo", sizeof(struct tcp_fragment), 0);
		if (echo == NULL) {
			printf("Failed to allocate echo fragment\n");
			return -1;
		}
		
		memset(echo, 0, sizeof(struct tcp_fragment));
		echo->sport = tcp_hdr->dst_port;
		echo->dport = tcp_hdr->src_port;
		echo->sent_seq = htonl(stream->snd_nxt);
		echo->recv_ack = htonl(stream->rcv_nxt);
		echo->tcp_flags = RTE_TCP_PSH_FLAG | RTE_TCP_ACK_FLAG;
		echo->rx_win = htons(TCP_RX_WIN);
		echo->data_off = 0x50;
		echo->length = payload_len;
		
		echo->data = rte_malloc("echo_payload", payload_len, 0);
		if (echo->data == NULL) {
			printf("Failed to allocate echo payload buffer\n");
			rte_free(echo);
			return -1;
		}
		
		unsigned char *payload = (unsigned char*)tcp_hdr + ((tcp_hdr->data_off >> 4) * 4);
		rte_memcpy(echo->data, payload, payload_len);

		ret = rte_ring_mp_enqueue(stream->sndbuf, echo);
		if (ret != 0) {
			printf("Failed to enqueue echo fragment\n");
			rte_free(echo->data);
			rte_free(echo);
			return -1;
		}

		/* Update send sequence number */
		stream->snd_nxt += payload_len;
	}

	return 0;
}

struct rte_mbuf*
encode_tcp_app_pktbuf(struct rte_mempool *mbuf_pool, uint16_t port_id, 
					  uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, 
					  uint8_t *srcmac, uint8_t *dstmac, struct tcp_fragment *fragment) 
{
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		printf("Error: Failed to allocate mbuf for TCP packet\n");
		return NULL;
	}

	/* Calculate total length */
	uint32_t total_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + 
						 sizeof(struct rte_tcp_hdr) + fragment->optlen * sizeof(uint32_t) + 
						 fragment->length;

	/* Ethernet header */
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	rte_memcpy(eth_hdr->dst_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth_hdr->src_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
	eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

	/* IPv4 header */
	struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
	ip_hdr->version_ihl = 0x45;
	ip_hdr->type_of_service = 0;
	ip_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + 
										   fragment->optlen * sizeof(uint32_t) + fragment->length);
	ip_hdr->packet_id = 0;
	ip_hdr->fragment_offset = 0;
	ip_hdr->time_to_live = 64;
	ip_hdr->next_proto_id = IPPROTO_TCP;
	ip_hdr->src_addr = sip;
	ip_hdr->dst_addr = dip;
	ip_hdr->hdr_checksum = 0;
	ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);

	/* TCP header */
	struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ip_hdr + 1);
	tcp_hdr->src_port = fragment->sport;
	tcp_hdr->dst_port = fragment->dport;
	tcp_hdr->sent_seq = fragment->sent_seq;
	tcp_hdr->recv_ack = fragment->recv_ack;
	tcp_hdr->data_off = fragment->data_off;
	tcp_hdr->rx_win = fragment->rx_win;
	tcp_hdr->tcp_urp = fragment->tcp_urp;
	tcp_hdr->tcp_flags = fragment->tcp_flags;

	/* Payload */
	if (fragment->data != NULL && fragment->length > 0) {
		char *payload = (char *)(tcp_hdr + 1) + fragment->optlen * sizeof(uint32_t);
		rte_memcpy(payload, fragment->data, fragment->length);
	}

	tcp_hdr->cksum = 0;
	tcp_hdr->cksum = rte_ipv4_udptcp_cksum(ip_hdr, tcp_hdr);

	/* Set mbuf properties */
	mbuf->data_len = total_len;
	mbuf->pkt_len = mbuf->data_len;
	return mbuf;
}

static int
tcp_output(struct rte_mempool *mbuf_pool) 
{
	struct tcp_table *table = tcp_instance();
	struct tcp_stream *iter;
	
	for (iter = table->tcp_set; iter != NULL; iter = iter->next) {
		struct tcp_fragment *fragment = NULL;
		int nb_snd = rte_ring_dequeue(iter->sndbuf, (void **)&fragment);
		if (nb_snd < 0) continue;

		uint8_t *dstmac = get_dst_macaddr(iter->sip);

		if (dstmac == NULL) {
			/* Need ARP resolution */
			struct rte_mbuf *arp_buf = encode_arp_pktmbuf(mbuf_pool, RTE_ARP_OP_REQUEST, 
														  g_default_arp_mac, iter->dip, iter->sip);
			if (arp_buf != NULL) {
				struct inout_ring *ring = ring_instance();
				int ret = rte_ring_mp_enqueue_burst(ring->out, (void **)&arp_buf, 1, NULL);
				if (ret != 1) {
					rte_pktmbuf_free(arp_buf);
				}
			}
			
			/* Re-enqueue fragment for later */
			rte_ring_mp_enqueue(iter->sndbuf, fragment);
		} else {
			struct rte_mbuf *tcp_mbuf = encode_tcp_app_pktbuf(mbuf_pool, g_dpdk_port_id, 
															  iter->dip, iter->sip, 
															  iter->sport, iter->dport, 
															  iter->localmac, dstmac, fragment);
			if (tcp_mbuf != NULL) {
				struct inout_ring *ring = ring_instance();
				int ret = rte_ring_mp_enqueue_burst(ring->out, (void **)&tcp_mbuf, 1, NULL);
				if (ret != 1) {
					rte_pktmbuf_free(tcp_mbuf);
				}
			}
			
			if (fragment->data != NULL) rte_free(fragment->data);
			rte_free(fragment);
		}
	}
	return 0;
}

static int
tcp_process(struct rte_mbuf *tcpmbuf) 
{
	struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(tcpmbuf, struct rte_ether_hdr *);
	struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(ehdr + 1);
	struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ip_hdr + 1);

	/* Validate TCP checksum */
	uint16_t original_cksum = tcp_hdr->cksum;
	tcp_hdr->cksum = 0;
	uint16_t calculated_cksum = rte_ipv4_udptcp_cksum(ip_hdr, tcp_hdr);
	tcp_hdr->cksum = original_cksum;

	if (calculated_cksum != original_cksum) {
		printf("TCP checksum error: calculated=%04x, received=%04x\n", 
			   calculated_cksum, original_cksum);
		rte_pktmbuf_free(tcpmbuf);
		return -1;
	}

	struct tcp_stream *stream = tcp_stream_search(ip_hdr->src_addr, ip_hdr->dst_addr,
												  tcp_hdr->src_port, tcp_hdr->dst_port);

	if (stream == NULL) {
		printf("No matching TCP stream found\n");
		rte_pktmbuf_free(tcpmbuf);
		return -2;
	}

	printf("==> TCP_process: flags=0x%02x, status=%d\n", tcp_hdr->tcp_flags, stream->status);
	int tcplen = ntohs(ip_hdr->total_length) - sizeof(struct rte_ipv4_hdr);

	switch (stream->status) {
		case TCP_STATUS_CLOSED:
			break;
				
		case TCP_STATUS_LISTEN:
			tcp_handle_listen(stream, tcp_hdr, ip_hdr);
			break;
		
		case TCP_STATUS_SYN_RCVD:
			tcp_handle_syn_rcvd(stream, tcp_hdr);
			break;
		
		case TCP_STATUS_SYN_SENT:
			break;

		case TCP_STATUS_ESTABLISHED:
			tcp_handle_established(stream, tcp_hdr, tcplen);
			break;
		
		case TCP_STATUS_FIN_WAIT_1:
		case TCP_STATUS_FIN_WAIT_2:
		case TCP_STATUS_CLOSING:
		case TCP_STATUS_TIME_WAIT:
		case TCP_STATUS_CLOSE_WAIT:
		case TCP_STATUS_LAST_ACK:
			/* TODO: Implement connection termination states */
			break;
	}

	rte_pktmbuf_free(tcpmbuf);
	return 0;
}
#endif

struct rte_mbuf*
encode_udp_app_pktbuf(struct rte_mempool *mbuf_pool, uint16_t port_id, 
					  uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, 
					  uint8_t *srcmac, uint8_t *dstmac, const char *data, int len) 
{
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		printf("Error: Failed to allocate mbuf for UDP packet\n");
		return NULL;
	}

	/* Ethernet header */
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	rte_memcpy(eth_hdr->dst_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth_hdr->src_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
	eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

	/* IPv4 header */
	struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
	ip_hdr->version_ihl = 0x45;
	ip_hdr->type_of_service = 0;
	ip_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + len);
	ip_hdr->packet_id = 0;
	ip_hdr->fragment_offset = 0;
	ip_hdr->time_to_live = 64;
	ip_hdr->next_proto_id = IPPROTO_UDP;
	ip_hdr->src_addr = sip;
	ip_hdr->dst_addr = dip;
	ip_hdr->hdr_checksum = 0;
	ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);

	/* UDP header */
	struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
	udp_hdr->src_port = sport;
	udp_hdr->dst_port = dport;
	udp_hdr->dgram_len = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) + len);
	udp_hdr->dgram_cksum = 0;

	/* Payload */
	if (len > 0 && data != NULL) {
		char *payload = (char *)(udp_hdr + 1);
		rte_memcpy(payload, data, len);
	}

	/* Set mbuf properties */
	mbuf->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + 
					 sizeof(struct rte_udp_hdr) + len;
	mbuf->pkt_len = mbuf->data_len;

	return mbuf;
}

static int
udp_output(struct rte_mempool *mbuf_pool) 
{
	struct localhost *host;
	for (host = g_lhost; host != NULL; host = host->next) {
		struct offload *ol;
		int nb_snd = rte_ring_mc_dequeue(host->sndbuf, (void **)&ol);
		if (nb_snd < 0) continue;

		uint8_t *dstmac = get_dst_macaddr(ol->dip);
		if (dstmac == NULL) {
			/* Need ARP resolution */
			struct rte_mbuf *arp_buf = encode_arp_pktmbuf(mbuf_pool, RTE_ARP_OP_REQUEST, 
														  g_default_arp_mac, ol->sip, ol->dip);
			if (arp_buf != NULL) {
				struct inout_ring *ring = ring_instance();
				int ret = rte_ring_mp_enqueue_burst(ring->out, (void **)&arp_buf, 1, NULL);
				if (ret != 1) {
					rte_pktmbuf_free(arp_buf);
				}
			}
			
			/* Re-enqueue for later */
			rte_ring_mp_enqueue(host->sndbuf, ol);
		} else {
			struct rte_mbuf *udp_buf = encode_udp_app_pktbuf(mbuf_pool, g_dpdk_port_id, 
															 ol->sip, ol->dip, ol->sport, ol->dport, 
															 host->localmac, dstmac,
															 (const char *)ol->data, ol->length);

			if (udp_buf != NULL) {
				struct inout_ring *ring = ring_instance();
				int ret = rte_ring_mp_enqueue_burst(ring->out, (void **)&udp_buf, 1, NULL);
				if (ret != 1) {
					rte_pktmbuf_free(udp_buf);
				}
			}

			if (ol->data) rte_free(ol->data);
			rte_free(ol);
		}
	}
	return 0;
}

static int
packet_process(__rte_unused void *arg)
{
	struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
	struct inout_ring *ring = ring_instance();

	while (1) {
		/* Process output queues */
#if ENABLE_UDP_APP
		udp_output(mbuf_pool);
#endif
#if ENABLE_TCP_APP
		tcp_output(mbuf_pool);
#endif

		struct rte_mbuf* mbufs[BURST_SIZE];
		unsigned nb_rx = rte_ring_mc_dequeue_burst(ring->in, (void **)mbufs, BURST_SIZE, NULL); 

		for (uint16_t i = 0; i < nb_rx; i++) {
			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);
			rte_memcpy(g_dst_mac, ehdr->src_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

			if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
#if ENABLE_ARP
				struct rte_arp_hdr *ahdr = (struct rte_arp_hdr *)(ehdr + 1);

				if (ahdr->arp_data.arp_tip != g_src_ip) {
					rte_pktmbuf_free(mbufs[i]);
					continue;
				}
				
				if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
					struct rte_mbuf *arpbuf = encode_arp_pktmbuf(mbuf_pool, RTE_ARP_OP_REPLY, 
																 ahdr->arp_data.arp_sha.addr_bytes,
																 ahdr->arp_data.arp_tip, 
																 ahdr->arp_data.arp_sip);
					
					if (arpbuf != NULL) {
						int ret = rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);
						if (ret != 1) {
							rte_pktmbuf_free(arpbuf);
						}
					}
				}
#endif

#if ENABLE_ARP_REPLY
				else if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
					struct arp_table *table = arp_table_instance();
					uint8_t *hwaddr = get_dst_macaddr(ahdr->arp_data.arp_sip);
					if (hwaddr == NULL) {
						struct arp_entry *entry = rte_malloc("arp_entry", sizeof(struct arp_entry), 0);
						if (entry) {
							memset(entry, 0, sizeof(struct arp_entry));
							entry->ip = ahdr->arp_data.arp_sip;
							rte_memcpy(entry->hwaddr, ahdr->arp_data.arp_sha.addr_bytes, RTE_ETHER_ADDR_LEN);
							entry->status = ARP_ENTRY_STATIC_DYNAMIC;

							LL_ADD(entry, table->entries);
							table->count++;
						}
					}
#if ENABLE_DEBUG
					struct arp_entry *iter;
					for (iter = table->entries; iter != NULL; iter = iter->next) {
						struct in_addr addr;
						addr.s_addr = iter->ip;
						printf("ARP entry added: %s\n", inet_ntoa(addr));
					}
#endif
				}
#endif
				rte_pktmbuf_free(mbufs[i]);	
				continue;
			}
			
			if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(ehdr + 1);
				
				if (ip_hdr->next_proto_id == IPPROTO_UDP) {
#if ENABLE_UDP_APP
					udp_process(mbufs[i]);
#else
					rte_pktmbuf_free(mbufs[i]);
#endif
				}
#if ENABLE_TCP_APP
				else if (ip_hdr->next_proto_id == IPPROTO_TCP) {
					tcp_process(mbufs[i]);
				}
#endif
#if ENABLE_ICMP
				else if (ip_hdr->next_proto_id == IPPROTO_ICMP) {
					struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(ip_hdr + 1);
					
					if (icmphdr->icmp_type == 8) {
						struct in_addr addr;
						addr.s_addr = ip_hdr->src_addr;
						printf("ICMP ping from %s", inet_ntoa(addr));
						addr.s_addr = ip_hdr->dst_addr;
						printf(" to %s\n", inet_ntoa(addr));

						struct rte_mbuf *txbuf = encode_icmp_pktbuf(mbuf_pool, ehdr->src_addr.addr_bytes,
																	ip_hdr->dst_addr, ip_hdr->src_addr, 
																	icmphdr->icmp_ident, icmphdr->icmp_seq_nb);

						if (txbuf != NULL) {
							int ret = rte_ring_mp_enqueue_burst(ring->out, (void **)&txbuf, 1, NULL);
							if (ret != 1) {
								rte_pktmbuf_free(txbuf);
							}
						}
					}
					rte_pktmbuf_free(mbufs[i]);
				}
#endif
				else {
					rte_pktmbuf_free(mbufs[i]);
				}
			} else {
				rte_pktmbuf_free(mbufs[i]);
			}
		}
	}
}
#endif

#if ENABLE_UDP_APP
static int nsocket(int domain, int type, int protocol) 
{
	int fd = get_fd_from_bitmap();
	
	if (type == SOCK_DGRAM) {
		struct localhost *host = rte_malloc("localhost", sizeof(struct localhost), 0);
		if (host == NULL) { 
			printf("Failed to allocate localhost structure\n");
			return -1; 
		}
		memset(host, 0, sizeof(struct localhost));

		host->fd = fd;
		host->protocol = IPPROTO_UDP;
		
		char ring_name[64];
		snprintf(ring_name, sizeof(ring_name), "UDP_RCVBUF_%d_%u", fd, (unsigned)time(NULL));
		host->rcvbuf = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(), 
									   RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (host->rcvbuf == NULL) {
			printf("Failed to create UDP receive buffer\n");
			rte_free(host);
			return -1;
		}

		snprintf(ring_name, sizeof(ring_name), "UDP_SNDBUF_%d_%u", fd, (unsigned)time(NULL));
		host->sndbuf = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(), 
									   RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (host->sndbuf == NULL) {
			printf("Failed to create UDP send buffer\n");
			rte_ring_free(host->rcvbuf);
			rte_free(host);
			return -1;
		}

		pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
		rte_memcpy(&host->cond, &blank_cond, sizeof(pthread_cond_t));

		pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
		rte_memcpy(&host->mutex, &blank_mutex, sizeof(pthread_mutex_t));

		LL_ADD(host, g_lhost);
	}
#if ENABLE_TCP_APP
	else if (type == SOCK_STREAM) {
		struct tcp_stream *stream = tcp_stream_create(0, 0, 0, 0);
		if (stream == NULL) {
			printf("Failed to create TCP stream\n");
			return -1;
		}
		stream->fd = fd;
	}
#endif

	return fd;
}

static int nbind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) 
{
	void *hostinfo = get_hostinfo_from_fd(sockfd);
	if (hostinfo == NULL) {
		printf("No host info found for socket %d\n", sockfd);
		return -1;
	}

	struct sockaddr_in *laddr = (struct sockaddr_in *)addr;
	struct localhost *host = (struct localhost *)hostinfo;

	if (host->protocol == IPPROTO_UDP) {
		host->localport = laddr->sin_port;
		rte_memcpy(&host->localip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
		rte_memcpy(host->localmac, g_src_mac, RTE_ETHER_ADDR_LEN);
	} 
#if ENABLE_TCP_APP
	else if (host->protocol == IPPROTO_TCP) {
		struct tcp_stream *stream = (struct tcp_stream *)hostinfo;
		stream->dport = laddr->sin_port;
		rte_memcpy(&stream->dip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
		rte_memcpy(stream->localmac, g_src_mac, RTE_ETHER_ADDR_LEN);
		stream->status = TCP_STATUS_CLOSED;
	}
#endif

	return 0;
}

static ssize_t nrecvfrom(int sockfd, void* buf, size_t len, int flags,
						 struct sockaddr *_src_addr, socklen_t * addrlen) 
{
	struct localhost *host = get_hostinfo_from_fd(sockfd);
	if (host == NULL) {
		printf("No host info found for socket %d\n", sockfd);
		return -1;
	}

	struct offload *ol = NULL;
	int nb = -1;

	pthread_mutex_lock(&host->mutex);
	while ((nb = rte_ring_mc_dequeue(host->rcvbuf, (void **)&ol)) < 0) {
		pthread_cond_wait(&host->cond, &host->mutex);
	}
	pthread_mutex_unlock(&host->mutex);
	
	if (_src_addr != NULL) {
		struct sockaddr_in *saddr = (struct sockaddr_in *)_src_addr;
		saddr->sin_port = ol->sport;
		rte_memcpy(&saddr->sin_addr.s_addr, &ol->sip, sizeof(uint32_t));
	}
	
	if (len < ol->length) {
		rte_memcpy(buf, ol->data, len);
		
		/* Create new buffer for remaining data */
		unsigned char *ptr = rte_malloc("remaining_data", ol->length - len, 0);
		if (ptr != NULL) {
			rte_memcpy(ptr, ol->data + len, ol->length - len);
			ol->length = ol->length - len;
			rte_free(ol->data);
			ol->data = ptr;
			rte_ring_mp_enqueue(host->rcvbuf, ol);
		} else {
			printf("Failed to allocate buffer for remaining data\n");
			rte_free(ol->data);
			rte_free(ol);
		}
		return len;
	} else {
		rte_memcpy(buf, ol->data, ol->length);
		int ret_len = ol->length;

		rte_free(ol->data);
		rte_free(ol);
		
		return ret_len;
	}
}

static ssize_t nsendto(int sockfd, const void *buf, size_t len, int flags,
					   const struct sockaddr *dest_addr, socklen_t addrlen) 
{
	struct localhost *host = get_hostinfo_from_fd(sockfd);
	if (host == NULL) {
		printf("No host info found for socket %d\n", sockfd);
		return -1;
	}

	struct sockaddr_in *daddr = (struct sockaddr_in *)dest_addr;

	struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
	if (ol == NULL) {
		printf("Failed to allocate offload structure\n");
		return -1;
	}

	ol->dip = daddr->sin_addr.s_addr;
	ol->dport = daddr->sin_port;
	ol->sip = host->localip;
	ol->sport = host->localport;
	ol->protocol = IPPROTO_UDP;
	ol->length = len;
	
	if (len > 0) {
		ol->data = rte_malloc("udp_send_data", len, 0);
		if (ol->data == NULL) {
			printf("Failed to allocate send data buffer\n");
			rte_free(ol);
			return -1;
		}
		rte_memcpy(ol->data, buf, len);
	} else {
		ol->data = NULL;
	}

	int ret = rte_ring_mp_enqueue(host->sndbuf, ol);
	if (ret != 0) {
		printf("Failed to enqueue send data\n");
		if (ol->data) rte_free(ol->data);
		rte_free(ol);
		return -1;
	}

	return len;
}

static int nclose(int fd) 
{
	void *hostinfo = get_hostinfo_from_fd(fd);
	if (hostinfo == NULL) {
		printf("No host info found for fd %d\n", fd);
		return -1;
	}

	/* Check if it's a UDP socket */
	struct localhost *host = NULL;
	for (host = g_lhost; host != NULL; host = host->next) {
		if (host->fd == fd) {
			break;
		}
	}

	if (host != NULL) {
		/* UDP socket cleanup */
		LL_REMOVE(host, g_lhost);

		if (host->rcvbuf) {
			/* Clean up any remaining data in receive buffer */
			struct offload *ol;
			while (rte_ring_dequeue(host->rcvbuf, (void **)&ol) == 0) {
				if (ol->data) rte_free(ol->data);
				rte_free(ol);
			}
			rte_ring_free(host->rcvbuf);
		}
		
		if (host->sndbuf) {
			/* Clean up any remaining data in send buffer */
			struct offload *ol;
			while (rte_ring_dequeue(host->sndbuf, (void **)&ol) == 0) {
				if (ol->data) rte_free(ol->data);
				rte_free(ol);
			}
			rte_ring_free(host->sndbuf);
		}

		rte_free(host);
		return 0;
	}

#if ENABLE_TCP_APP
	/* Check if it's a TCP socket */
	struct tcp_table *table = tcp_instance();
	struct tcp_stream *stream;
	for (stream = table->tcp_set; stream != NULL; stream = stream->next) {
		if (stream->fd == fd) {
			break;
		}
	}

	if (stream != NULL) {
		/* TCP socket cleanup */
		LL_REMOVE(stream, table->tcp_set);
		table->count--;

		if (stream->rcvbuf) {
			/* Clean up any remaining fragments in receive buffer */
			struct tcp_fragment *frag;
			while (rte_ring_dequeue(stream->rcvbuf, (void **)&frag) == 0) {
				if (frag->data) rte_free(frag->data);
				rte_free(frag);
			}
			rte_ring_free(stream->rcvbuf);
		}
		
		if (stream->sndbuf) {
			/* Clean up any remaining fragments in send buffer */
			struct tcp_fragment *frag;
			while (rte_ring_dequeue(stream->sndbuf, (void **)&frag) == 0) {
				if (frag->data) rte_free(frag->data);
				rte_free(frag);
			}
			rte_ring_free(stream->sndbuf);
		}

		rte_free(stream);
		return 0;
	}
#endif

	return -1;
}

int udp_server_entry(void *argv) 
{
	int connfd = nsocket(AF_INET, SOCK_DGRAM, 0);
	if (connfd == -1) {
		printf("Failed to create UDP socket\n");
		return -1;
	}

	struct sockaddr_in localaddr, clientaddr;
	memset(&localaddr, 0, sizeof(struct sockaddr_in));

	localaddr.sin_port = htons(8888);
	localaddr.sin_family = AF_INET;
	localaddr.sin_addr.s_addr = inet_addr("192.168.0.120");

	if (nbind(connfd, (struct sockaddr *)&localaddr, sizeof(struct sockaddr_in)) != 0) {
		printf("Failed to bind UDP socket\n");
		nclose(connfd);
		return -1;
	}

	char buffer[UDP_APP_RECV_BUFFER_SIZE] = { 0 };
	socklen_t addrlen = sizeof(clientaddr);
	
	printf("UDP server listening on port 8888\n");
	
	while (1) {
		memset(buffer, 0, UDP_APP_RECV_BUFFER_SIZE);
		
		ssize_t recv_len = nrecvfrom(connfd, buffer, UDP_APP_RECV_BUFFER_SIZE, 0,
									 (struct sockaddr *)&clientaddr, &addrlen);
		if (recv_len > 0) {
			printf("Received from %s:%d, content: %s\n", 
				   inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port), buffer);

			ssize_t send_len = nsendto(connfd, buffer, recv_len, 0,
									   (struct sockaddr *)&clientaddr, sizeof(clientaddr));	
			if (send_len < 0) {
				printf("Failed to send UDP response\n");
			}
		}
	}

	nclose(connfd);
	return 0;
}
#endif

#if ENABLE_TCP_APP
int nlisten(int sockfd, __attribute__((unused)) int backlog) 
{
	void *hostinfo = get_hostinfo_from_fd(sockfd);
	if (hostinfo == NULL) {
		printf("No host info found for socket %d\n", sockfd);
		return -1;
	}
	
	struct tcp_stream *stream = (struct tcp_stream *)hostinfo;
	if (stream->proto == IPPROTO_TCP) {
		stream->status = TCP_STATUS_LISTEN;
		printf("TCP socket %d set to LISTEN state\n", sockfd);
	}

	return 0;
}

int naccept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) 
{
	/* TODO: Implement TCP accept functionality */
	printf("TCP accept not yet implemented\n");
	return -1;
}

ssize_t nsend(int sockfd, const void *buf, size_t len, int flags) 
{
	/* TODO: Implement TCP send functionality */
	printf("TCP send not yet implemented\n");
	return -1;
}

ssize_t nrecv(int sockfd, void *buf, size_t len, int flags) 
{
	/* TODO: Implement TCP receive functionality */
	printf("TCP recv not yet implemented\n");
	return -1;
}
#endif

/* Standard socket functions for testing */
#define BUFFER_SIZE		1024

static int
tcp_server_entry(void* arg) 
{
	int listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd == -1) {
		printf("Failed to create TCP socket\n");
		return -1;
	}

	struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(struct sockaddr_in));
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(8889);
	
	if (bind(listenfd, (struct sockaddr *)&servaddr, sizeof(struct sockaddr)) != 0) {
		printf("Failed to bind TCP socket\n");
		close(listenfd);
		return -1;
	}

	if (listen(listenfd, 10) != 0) {
		printf("Failed to listen on TCP socket\n");
		close(listenfd);
		return -1;
	}

	printf("TCP server listening on port 8889\n");

	struct sockaddr_in clientaddr;
	socklen_t len = sizeof(struct sockaddr_in);
	int connfd = accept(listenfd, (struct sockaddr *)&clientaddr, &len);
	if (connfd < 0) {
		printf("Failed to accept TCP connection\n");
		close(listenfd);
		return -1;
	}

	char buffer[BUFFER_SIZE] = { 0 };
	while (1) {
		int nb_rcv = recv(connfd, buffer, BUFFER_SIZE, 0);
		if (nb_rcv > 0) {
			send(connfd, buffer, nb_rcv, 0);
		} else if (nb_rcv == 0) {
			printf("TCP client disconnected\n");
			break;
		} else {
			printf("TCP receive error\n");
			break;
		}
	}
	
	close(connfd);
	close(listenfd);
	return 0;
}

int main(int argc, char *argv[]) 
{
	int ret;
	unsigned int lcore_id;

	/* Initialize EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Error: Cannot init EAL\n");
	}

	/* Create memory pool with better error handling */
	g_mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
										  RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (g_mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Error: Cannot create mbuf pool: %s\n", rte_strerror(rte_errno));
	}

	/* Initialize port */
	g_dpdk_port_id = 0;
	ret = init_port(g_dpdk_port_id);
	if (ret != 0) {
		rte_exit(EXIT_FAILURE, "Error: Cannot init port %u\n", g_dpdk_port_id);
	}

	/* Set IP and port */
	g_src_ip = g_local_ip;
	g_src_port = rte_cpu_to_be_16(8888);

/* Initialize timer subsystem */
#if ENABLE_TIMER
	rte_timer_subsystem_init();

	static struct rte_timer arp_timer;
	rte_timer_init(&arp_timer);

	uint64_t hz = rte_get_timer_hz();
	lcore_id = rte_lcore_id();
	printf("Timer setup - hz: %lu, lcore_id: %u\n", hz, lcore_id);
	
	ret = rte_timer_reset(&arp_timer, hz, PERIODICAL, lcore_id, arp_request_timer_cb, g_mbuf_pool);
	if (ret != 0) {
		printf("Failed to reset timer: %d\n", ret);
	} else {
		printf("Timer reset successfully\n");
	}
#endif

/* Initialize ring buffers */
#if ENABLE_RINGBUFFER
	struct inout_ring *ring = ring_instance();
	if (ring == NULL) {
		rte_exit(EXIT_FAILURE, "Ring buffer init failed\n");
	}

	if (ring->in == NULL) {
		ring->in = rte_ring_create("in_ring", RING_SIZE, rte_socket_id(), 
								   RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (ring->in == NULL) {
			rte_exit(EXIT_FAILURE, "Failed to create input ring\n");
		}
	}

	if (ring->out == NULL) {
		ring->out = rte_ring_create("out_ring", RING_SIZE, rte_socket_id(), 
									RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (ring->out == NULL) {
			rte_exit(EXIT_FAILURE, "Failed to create output ring\n");
		}
	}
#endif

/* Launch worker threads */
#if ENABLE_MULTITHREAD
	lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	if (lcore_id == RTE_MAX_LCORE) {
		printf("Warning: No available lcore for packet processing\n");
	} else {
		rte_eal_remote_launch(packet_process, g_mbuf_pool, lcore_id);
	}
#endif

#if ENABLE_UDP_APP
	lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	if (lcore_id == RTE_MAX_LCORE) {
		printf("Warning: No available lcore for UDP server\n");
	} else {
		rte_eal_remote_launch(udp_server_entry, g_mbuf_pool, lcore_id);
	}
#endif

	printf("Starting main packet processing loop\n");

	/* Main loop: receive and transmit packets */
	while (1) {
		struct rte_mbuf *rx[PKT_BURST];
		uint16_t nb_rx = rte_eth_rx_burst(g_dpdk_port_id, 0, rx, PKT_BURST);
		
		if (nb_rx > 0) {
#if ENABLE_RINGBUFFER
			struct inout_ring *ring = ring_instance();
			uint16_t nb_enqueued = rte_ring_sp_enqueue_burst(ring->in, (void **)rx, nb_rx, NULL);
			
			/* Free any packets that couldn't be enqueued */
			for (uint16_t i = nb_enqueued; i < nb_rx; i++) {
				rte_pktmbuf_free(rx[i]);
			}
#else
			/* If no ring buffer, free all packets */
			for (uint16_t i = 0; i < nb_rx; i++) {
				rte_pktmbuf_free(rx[i]);
			}
#endif
		}

#if ENABLE_RINGBUFFER
		/* Transmit packets */
		struct rte_mbuf *tx[PKT_BURST];
		struct inout_ring *ring = ring_instance();
		unsigned nb_tx = rte_ring_sc_dequeue_burst(ring->out, (void **)tx, BURST_SIZE, NULL);
		if (nb_tx > 0) {
			uint16_t nb_sent = rte_eth_tx_burst(g_dpdk_port_id, 0, tx, nb_tx);
			
			/* Free any unsent packets */
			for (unsigned int i = nb_sent; i < nb_tx; i++) {
				rte_pktmbuf_free(tx[i]);
			}
		}
#endif

#if ENABLE_TIMER
		static uint64_t prev_tsc = 0, cur_tsc;
		uint64_t diff_tsc;

		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;

		if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
			rte_timer_manage();
			prev_tsc = cur_tsc;
		}
#endif
	}

	/* Cleanup */
	rte_eth_dev_stop(g_dpdk_port_id);
	rte_eth_dev_close(g_dpdk_port_id);
	rte_eal_cleanup();
	return 0;
}