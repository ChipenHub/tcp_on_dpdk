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

#define RING_SIZE 					1024
#define NUM_MBUFS 					8191
#define MBUF_CACHE_SIZE 			250
#define RX_RING_SIZE 				1024
#define TX_RING_SIZE 				1024
#define PKT_BURST 					32
#define BURST_SIZE					32
#define TCP_OPTIONAL_LENGTH			10
#define TCP_MAX_SEQ					4294967295
#define TCP_RX_WIN					14600

#define UDP_APP_RECV_BUFFER_SIZE	128

#define TIMER_RESOLUTION_CYCLES 	60000000000ULL

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))
static uint32_t gLocalIp = MAKE_IPV4_ADDR(192, 168, 0, 120);

static uint16_t gDpdkPortId = 0;
static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
static uint8_t gDstMac[RTE_ETHER_ADDR_LEN];
static uint32_t gSrcIp;		// 大端存储
static uint32_t gDstIp;
static uint16_t gSrcPort;
static uint16_t gDstPort;

static struct rte_mempool *mbuf_pool = NULL;

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

#define DEFAULT_FD_NB	3
static struct localhost *lhost = NULL;

#if ENABLE_ARP_REPLY
#include "arp.h"
static uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
#endif

#if ENABLE_RINGBUFFER
struct inout_ring {
	struct rte_ring *in;
	struct rte_ring *out;
};

static struct inout_ring *rInst = NULL;

struct inout_ring *ring_instance(void) {
	if (rInst == NULL) {
		rInst = rte_malloc("in/out ring", sizeof (struct inout_ring), 0);
		memset(rInst, 0, sizeof (struct inout_ring));
	}
	return rInst;
}
#endif

// 计算校验和
static uint16_t checksum(uint16_t *addr, int count) {
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
static int fd_counter = DEFAULT_FD_NB;

int get_fd_from_bitmap() {
	return ++fd_counter;
}

struct localhost *
get_hostinfo_from_fd(int sockfd) {
	struct localhost *host;
	for (host = lhost; host != NULL; host = host->next)
		if (sockfd == host->fd)
			return host;
	return NULL;
}

struct localhost *
get_hostinfo_from_ipport(uint32_t dip, uint16_t port, uint8_t proto) {
	struct localhost *host;
	for (host = lhost; host != NULL; host = host->next)
		if (dip == host->localip &&
			port == host->localport &&
			proto == host->protocol)
			return host;
	return NULL;
}
#endif

// 初始化网卡
static int init_port(uint16_t port_id) {
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
                                 rte_eth_dev_socket_id(port_id), NULL, mbuf_pool);
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

    rte_eth_macaddr_get(port_id, (struct rte_ether_addr *)gSrcMac);
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           gSrcMac[0], gSrcMac[1], gSrcMac[2], gSrcMac[3], gSrcMac[4], gSrcMac[5]);

    return 0;
}

#if ENABLE_ARP
struct rte_mbuf* encode_arp_pktmbuf(struct rte_mempool *mbuf_pool, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "Error: Failed to allocate mbuf\n");
    }

	const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
	mbuf->pkt_len = total_length;
	mbuf->data_len = total_length;

	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);

	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt_data;
	rte_memcpy(eth->src_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);

	if (dst_mac == NULL || !strncmp((const char *)dst_mac, (const char *)gDefaultArpMac, RTE_ETHER_ADDR_LEN)) {
		memset(eth->dst_addr.addr_bytes, 0xFF, RTE_ETHER_ADDR_LEN);
	} else {
		rte_memcpy(eth->dst_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	}

	eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

	// 2 arp 
	struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
	arp->arp_hardware = htons(1);
	arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
	arp->arp_hlen = RTE_ETHER_ADDR_LEN;
	arp->arp_plen = sizeof(uint32_t);
	arp->arp_opcode = htons(opcode);

	rte_memcpy(arp->arp_data.arp_sha.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	
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
struct rte_mbuf *encode_icmp_pktbuf(struct rte_mempool *mbuf_pool, uint8_t *dst_mac,
		uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb) {

	const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr);

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}

	mbuf->pkt_len = total_length;
	mbuf->data_len = total_length;

	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);

	// 1 ether
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt_data;
	rte_memcpy(eth->src_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->dst_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	// 2 ip
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

	// 3 icmp 
	struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(pkt_data+ sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
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
arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim, void *arg) {
	printf("ARP timer callback started\n");
	
	struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
	struct inout_ring *ring = ring_instance();
	if (mbuf_pool == NULL) {
		printf("Error: mbuf_pool is NULL in timer callback\n");
		return;
	}

	printf("arp_request ---> ");

	int i = 0; 
	for (i = 1; i < 255; i++) {
		uint32_t dstip = (gLocalIp & 0x00FFFFFF) | (0xFF000000 & (i << 24));
		uint8_t* dstmac = get_dst_macaddr(dstip);

		struct in_addr addr;
		addr.s_addr = dstip;
		printf("%s ", inet_ntoa(addr));

		struct rte_mbuf * arp_buf = encode_arp_pktmbuf(mbuf_pool, RTE_ARP_OP_REQUEST, dstmac, gLocalIp, dstip);
		if (arp_buf != NULL) {
			uint16_t nb_tx = rte_ring_mp_enqueue_burst(ring->out, (void **)&arp_buf, 1, NULL);
			if (nb_tx != 1) {
				printf("Failed to send ARP request for IP %s\n", inet_ntoa(addr));
			}
		}
	}
	puts("");
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
UDP_process(struct rte_mbuf *mbuf) {
	struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(ehdr + 1);
	struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
	
	struct localhost *host = get_hostinfo_from_ipport(ip_hdr->dst_addr, udp_hdr->dst_port, ip_hdr->next_proto_id);
	if (host == NULL) {
		return -3;
	}

	struct offload *ol = rte_malloc("malloc", sizeof (struct offload), 0);
	if (ol == NULL) {
		rte_pktmbuf_free(mbuf);
		return -1;
	}

	ol->sip = ip_hdr->src_addr;
	ol->sport = udp_hdr->src_port;
	ol->dip = ip_hdr->dst_addr; 
	ol->dport = udp_hdr->dst_port;
	ol->protocol = IPPROTO_UDP;
	ol->length = ntohs(udp_hdr->dgram_len) - sizeof(struct rte_udp_hdr);

	ol->data = rte_malloc("unsigned char *", ol->length, 0);
	if (ol->data == NULL) {
		rte_pktmbuf_free(mbuf);
		rte_free(ol);
		return -2;
	}

	rte_memcpy(ol->data, (unsigned char *)(udp_hdr + 1), ol->length);

	rte_ring_mp_enqueue(host->rcvbuf, ol);

	pthread_mutex_lock(&host->mutex);
	pthread_cond_signal(&host->cond);
	pthread_mutex_unlock(&host->mutex);
	
	rte_pktmbuf_free(mbuf);
	return 0;
}
#endif


#if ENABLE_TCP_APP

typedef enum TCP_STATUS {

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

} TCP_STATUS;



struct tcp_stream {

	int fd;

	uint32_t sip;
	uint32_t dip;

	uint16_t sport;
	uint16_t dport;

	uint16_t proto;

	uint8_t localmac[RTE_ETHER_ADDR_LEN];

	struct rte_ring *sndbuf;
	struct rte_ring *rcvbuf;

	struct tcp_stream *prev;
	struct tcp_stream *next;

	TCP_STATUS status;
	
	
	uint32_t snd_nxt; // seqnum
	uint32_t rcv_nxt; // acknum

};

struct tcp_fragment {

	rte_be16_t sport; /**< TCP source port. */
	rte_be16_t dport; /**< TCP destination port. */
	rte_be32_t sent_seq; /**< TX data sequence number. */
	rte_be32_t recv_ack; /**< RX data acknowledgment sequence number. */
	uint8_t  data_off;   /**< Data offset. */
	uint8_t  tcp_flags;  /**< TCP flags */
	rte_be16_t rx_win;   /**< RX flow control window. */
	rte_be16_t cksum;    /**< TCP checksum. */
	rte_be16_t tcp_urp;  /**< TCP urgent pointer, if any. */

	int optlen;
	uint32_t option[TCP_OPTIONAL_LENGTH];

	unsigned char *data;
	int length;

};

struct tcp_table {
	int count;
	struct tcp_stream *tcp_set;
};

static struct tcp_table *tInst = NULL;
static struct tcp_table *tcp_instance() {

	if (tInst == NULL) {

		tInst = rte_malloc("tcp_malloc", sizeof (struct tcp_table), 0);
		memset(tInst, 0, sizeof (struct tcp_table));

	}

	return tInst;	

}

static struct tcp_stream*
tcp_stream_search(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) {

	struct tcp_table *table = tcp_instance();

	struct tcp_stream *iter;
	for (iter = table->tcp_set; iter != NULL; iter = iter->next) {

		if (iter->dip == dip && iter->sip == sip && iter->dport == dport && iter->sport == sport) {

			return iter;
		
		}
	
	}

	return NULL;

}


static struct tcp_stream*
tcp_stream_create(uint32_t sip, uint32_t dip, uint8_t sport, uint8_t dport) {

	char stream_name[32];
	snprintf(stream_name, sizeof(stream_name), "TCPstream_%d", tInst->count);
	struct tcp_stream *stream = rte_malloc(stream_name, sizeof (struct tcp_stream), 0);
	
	stream->dip = dip;
	stream->sip = sip;
	stream->dport = dport;
	stream->sport = sport;
	stream->fd = get_fd_from_bitmap();

	stream->proto = IPPROTO_TCP;
	stream->status = TCP_STATUS_LISTEN;

	snprintf(stream_name, sizeof(stream_name), "SNDBUF_%d", tInst->count);
	stream->sndbuf = rte_ring_create(stream_name, RING_SIZE, rte_socket_id(), 0);

	snprintf(stream_name, sizeof(stream_name), "RCVBUF_%d", tInst->count);
	stream->rcvbuf = rte_ring_create(stream_name, RING_SIZE, rte_socket_id(), 0);


	uint32_t next_seed = time(NULL);
	stream->snd_nxt = rand_r(&next_seed) % TCP_MAX_SEQ;

	rte_memcpy(stream->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);
	struct tcp_table *table = tcp_instance();
	LL_ADD(stream, table->tcp_set);
	
	return stream;

	
	
}

static int
tcp_handle_listen(struct tcp_stream *stream, struct rte_tcp_hdr *tcp_hdr) {

	if (tcp_hdr->tcp_flags & RTE_TCP_SYN_FLAG) {

		if (stream->status == TCP_STATUS_LISTEN) {



			// TODO
			struct tcp_fragment *fragment = rte_malloc("TTTTODO", sizeof (struct tcp_fragment), 0);
			if (fragment == NULL) return -1;

			memset(fragment, 0, sizeof (struct tcp_fragment));
			fragment->sport = tcp_hdr->dst_port;
			fragment->dport = tcp_hdr->src_port;

			fragment->sent_seq = stream->snd_nxt;
			fragment->recv_ack = ntohl(tcp_hdr->sent_seq) + 1;

			fragment->tcp_flags = (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG);

			fragment->rx_win = TCP_RX_WIN;
			fragment->data_off = 0x50;
			fragment->data = NULL;

			fragment->length = 0;

			rte_ring_mp_enqueue(stream->sndbuf, fragment);
			
			
			stream->status = TCP_STATUS_SYN_RCVD;


		}
	
	}


	return 0;
}

static int
tcp_handle_syn_rcvd(struct tcp_stream *stream, struct rte_tcp_hdr *tcp_hdr) {

	if (tcp_hdr->tcp_flags & RTE_TCP_ACK_FLAG) {

		if (stream->status == TCP_STATUS_SYN_RCVD) {

			uint32_t ack_num = ntohl(tcp_hdr->recv_ack);
			if (ack_num == stream->snd_nxt + 1) {

				

			}

			stream->status = TCP_STATUS_ESTABLISHED;
		}

	}

	
	return 0;
}


struct rte_mbuf*
encode_tcp_app_pktbuf(struct rte_mempool *mbuf_pool,
			uint16_t port_id, uint32_t sip, uint32_t dip, uint16_t sport,
			uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
			struct tcp_fragment *fragment) {
			
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
		rte_exit(EXIT_FAILURE, "Error: Failed to allocate mbuf\n");
    }

    // 以太网头部
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    rte_memcpy(eth_hdr->dst_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth_hdr->src_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    // IPv4 头部
    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    ip_hdr->version_ihl = 0x45;
    ip_hdr->type_of_service = 0;
    ip_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + fragment->length);
    ip_hdr->packet_id = 0;
    ip_hdr->fragment_offset = 0;
    ip_hdr->time_to_live = 64;
    ip_hdr->next_proto_id = IPPROTO_TCP;
    ip_hdr->src_addr = sip;
    ip_hdr->dst_addr = dip;
    ip_hdr->hdr_checksum = 0;
    ip_hdr->hdr_checksum = checksum((uint16_t *)ip_hdr, sizeof(struct rte_ipv4_hdr));

    // TCP 头部
    struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ip_hdr + 1);
    tcp_hdr->src_port = fragment->sport;
    tcp_hdr->dst_port = fragment->dport;
	tcp_hdr->sent_seq = htonl(fragment->sent_seq);
	tcp_hdr->recv_ack = htonl(fragment->recv_ack);

	tcp_hdr->data_off = fragment->data_off;
	tcp_hdr->rx_win = fragment->rx_win;
	tcp_hdr->tcp_urp = fragment->tcp_urp;
	tcp_hdr->tcp_flags = fragment->tcp_flags;


    // 数据载荷
	if (fragment->data != NULL) {

	    char *payload = (char *)(tcp_hdr + 1) + fragment->optlen * sizeof (uint32_t);
    	memcpy(payload, fragment->data, fragment->length);

	}

	tcp_hdr->cksum = 0;
	tcp_hdr->cksum = rte_ipv4_udptcp_cksum(ip_hdr, tcp_hdr);

    // 设置 mbuf
    mbuf->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
    				sizeof(struct rte_tcp_hdr) + fragment->length + fragment->optlen + sizeof (uint32_t);

    mbuf->pkt_len = mbuf->data_len;
	return mbuf;
}


static int
TCP_OUT(struct rte_mempool *mbuf_pool) {

	struct tcp_table *table = tcp_instance();
	struct tcp_stream *iter;
	for (iter = table->tcp_set; iter != NULL; iter = iter->next) {

		struct tcp_fragment *fragment = NULL;
		int nb_snd = rte_ring_dequeue(iter->sndbuf, (void **)&fragment);
		if (nb_snd < 0) continue;

		uint8_t *dstmac = get_dst_macaddr(iter->sip);

		if (dstmac == NULL) {
			struct rte_mbuf *arp_buf = encode_arp_pktmbuf(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, iter->sip, iter->dip);
			struct inout_ring *ring = ring_instance();
			rte_ring_mp_enqueue_burst(ring->out, (void **)&arp_buf, 1, NULL);
			rte_ring_mp_enqueue(iter->sndbuf, fragment);
		} else {

			struct rte_mbuf *tcp_mbuf = encode_tcp_app_pktbuf(mbuf_pool, gDpdkPortId, iter->dip, iter->sip, iter->sport, iter->dport, iter->localmac, dstmac, fragment);
			struct inout_ring *ring = ring_instance();
			rte_ring_mp_enqueue_burst(ring->out, (void **)&tcp_mbuf, 1, NULL);

			rte_free(fragment);

			
		}
				
		
	}
	return 0;
	
}

static int
TCP_process(struct rte_mbuf *tcpmbuf) {

	struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(tcpmbuf, struct rte_ether_hdr *);
	struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(ehdr + 1);
	struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ip_hdr + 1);

	uint16_t cksum = rte_ipv4_udptcp_cksum(ip_hdr, tcp_hdr);

	if (cksum != ntohs(tcp_hdr->cksum)) {
		return -1;
	}

	
	struct tcp_stream *stream = tcp_stream_search(ip_hdr->src_addr, ip_hdr->dst_addr,
	tcp_hdr->src_port, tcp_hdr->dst_port);

	if (stream == NULL) {
		stream = tcp_stream_create(ip_hdr->src_addr, ip_hdr->dst_addr, tcp_hdr->src_port, tcp_hdr->dst_port);		
		if (stream == NULL) return -2;
	}

	printf("==> TCP_process\n");


	switch (stream->status) {

		case TCP_STATUS_CLOSED:
			break;
				
		case TCP_STATUS_LISTEN:
			tcp_handle_listen(stream, tcp_hdr);
			break;
		
		case TCP_STATUS_SYN_RCVD:
			tcp_handle_syn_rcvd(stream, tcp_hdr);
			break;
		
		case TCP_STATUS_SYN_SENT:
			break;

		case TCP_STATUS_ESTABLISHED:
			break;
		
		case TCP_STATUS_FIN_WAIT_1:
			break;
		
		case TCP_STATUS_FIN_WAIT_2:
			break;
				
		case TCP_STATUS_CLOSING:
			break;
		
		case TCP_STATUS_TIME_WAIT:
			break;
		
		case TCP_STATUS_CLOSE_WAIT:
			break;
		
		case TCP_STATUS_LAST_ACK:
			break;
		

	}

}


#endif



struct rte_mbuf*
encode_udp_app_pktbuf(struct rte_mempool *mbuf_pool,
			uint16_t port_id, uint32_t sip, uint32_t dip, uint16_t sport,
			uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
			const char *data, int len) {
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
		rte_exit(EXIT_FAILURE, "Error: Failed to allocate mbuf\n");
    }

    // 以太网头部
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    rte_memcpy(eth_hdr->dst_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth_hdr->src_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    // IPv4 头部
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
    ip_hdr->hdr_checksum = checksum((uint16_t *)ip_hdr, sizeof(struct rte_ipv4_hdr));

    // UDP 头部
    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
    udp_hdr->src_port = sport;
    udp_hdr->dst_port = dport;
    udp_hdr->dgram_len = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) + len);
    udp_hdr->dgram_cksum = 0;

    // 数据载荷
    char *payload = (char *)(udp_hdr + 1);
    memcpy(payload, data, len);

    // 设置 mbuf
    mbuf->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + len;
    mbuf->pkt_len = mbuf->data_len;

	return mbuf;
}

static int
UDP_OUT(struct rte_mempool *mbuf_pool) {
	struct localhost *host;
	for (host = lhost; host != NULL; host = host->next) {
		struct offload *ol;
		int nb_snd = rte_ring_mc_dequeue(host->sndbuf, (void **)&ol);
		if (nb_snd < 0) continue;

		uint8_t *dstmac = get_dst_macaddr(ol->dip);
		if (dstmac == NULL) {
			struct rte_mbuf *arp_buf = encode_arp_pktmbuf(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, ol->sip, ol->dip);
			struct inout_ring *ring = ring_instance();
			rte_ring_mp_enqueue_burst(ring->out, (void **)&arp_buf, 1, NULL);
			rte_ring_mp_enqueue(host->sndbuf, ol);
		} else {
			struct rte_mbuf *udp_buf= encode_udp_app_pktbuf(mbuf_pool,
			gDpdkPortId, ol->sip, ol->dip, ol->sport,
			ol->dport, host->localmac, dstmac,
			(const char *)ol->data, ol->length);

			struct inout_ring *ring = ring_instance();
			rte_ring_mp_enqueue_burst(ring->out, (void **)&udp_buf, 1, NULL);

			rte_free(ol->data);
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
		// 处理输出队列

#if ENABLE_UDP_APP
		UDP_OUT(mbuf_pool);
#endif
#if ENABLE_TCP_APP
		TCP_OUT(mbuf_pool);
#endif

		struct rte_mbuf* mbufs[BURST_SIZE];
		unsigned nb_rx = rte_ring_mc_dequeue_burst(ring->in, (void **)mbufs, BURST_SIZE, NULL); 

        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);
			rte_memcpy(gDstMac, ehdr->src_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

			if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
#if ENABLE_ARP
				struct rte_arp_hdr *ahdr = (struct rte_arp_hdr *)(ehdr + 1);

				if (ahdr->arp_data.arp_tip != gSrcIp) {
					rte_pktmbuf_free(mbufs[i]);
					continue;
				}
				
				if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
					struct in_addr addr;
					addr.s_addr = ahdr->arp_data.arp_sip;
					printf("arp ---> src: %s", inet_ntoa(addr));

					addr.s_addr = ahdr->arp_data.arp_tip;
					printf("  local: %s\n", inet_ntoa(addr));

					struct rte_mbuf *arpbuf = encode_arp_pktmbuf(mbuf_pool, RTE_ARP_OP_REPLY, ahdr->arp_data.arp_sha.addr_bytes,
						ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);
					
					rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);
					printf("ARP enqueue finished\n");

					rte_pktmbuf_free(mbufs[i]);
					continue;
				}
#endif

#if ENABLE_ARP_REPLY
				else if (ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
					struct arp_table *table = arp_table_instance();
					uint8_t *hwaddr = get_dst_macaddr(ahdr->arp_data.arp_sip);
					if (hwaddr == NULL) {
						struct arp_entry *entry = rte_malloc("arp entry", sizeof(struct arp_entry), 0);
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
						print_ether_addr("arp entry ---> mac: ", (struct rte_ether_addr *) iter->hwaddr);
						struct in_addr addr;
						addr.s_addr = iter->ip;
						printf(" ---> src: %s\n", inet_ntoa(addr));
					}
#endif
				}
				
				rte_pktmbuf_free(mbufs[i]);	
				continue;
#endif
			}
			
		    if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(ehdr + 1);
				
		   		if (ip_hdr->next_proto_id == IPPROTO_UDP) {
					printf("UDP ===> \n");
					UDP_process(mbufs[i]);
				}

#if ENABLE_TCP_APP

				else if (ip_hdr->next_proto_id == IPPROTO_TCP) {
					TCP_process(mbufs[i]);
				}

#endif

#if ENABLE_ICMP
				else if (ip_hdr->next_proto_id == IPPROTO_ICMP) {
					struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(ip_hdr + 1);
					
					if (icmphdr->icmp_type == 8) {
						struct in_addr addr;
						addr.s_addr = ip_hdr->src_addr;
						printf("icmp ---> src: %s", inet_ntoa(addr));
						addr.s_addr = ip_hdr->dst_addr;
						printf("  local: %s, type: %d\n", inet_ntoa(addr), icmphdr->icmp_type);

						struct rte_mbuf *txbuf = encode_icmp_pktbuf(mbuf_pool, ehdr->src_addr.addr_bytes,
							ip_hdr->dst_addr, ip_hdr->src_addr, icmphdr->icmp_ident, icmphdr->icmp_seq_nb);

						rte_ring_mp_enqueue_burst(ring->out, (void **)&txbuf, 1, NULL);
						rte_pktmbuf_free(mbufs[i]);
					}
				}
#endif
		    } else {
				// 如果包没有被处理，释放它
				rte_pktmbuf_free(mbufs[i]);
			}
        }
	}
}
#endif

#if ENABLE_UDP_APP
static int nsocket(int domain, int type, int protocol) {
	int fd = get_fd_from_bitmap();

	struct localhost *host = rte_malloc("localhost", sizeof (struct localhost), 0);
	if (host == NULL) { return -1; }
	memset(host, 0, sizeof (struct localhost));

	host->fd = fd;
	
	if (type == SOCK_DGRAM)
		host->protocol = IPPROTO_UDP;
	else if (type == SOCK_STREAM)
		host->protocol = IPPROTO_TCP;

	char ring_name[32];
	snprintf(ring_name, sizeof(ring_name), "rcvbuf_%d", fd);
	host->rcvbuf = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (host->rcvbuf == NULL) {
		rte_free(host);
		return -1;
	}

	snprintf(ring_name, sizeof(ring_name), "sndbuf_%d", fd);
	host->sndbuf = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (host->sndbuf == NULL) {
		rte_ring_free(host->rcvbuf);
		rte_free(host);
		return -1;
	}

	pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
	rte_memcpy(&host->cond, &blank_cond, sizeof (pthread_cond_t));

	pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
	rte_memcpy(&host->mutex, &blank_mutex, sizeof (pthread_mutex_t));
	
	LL_ADD(host, lhost);

	return fd;
}

static int nbind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	struct localhost *host = get_hostinfo_from_fd(sockfd);
	if (host == NULL) return -1;

	struct sockaddr_in *laddr = (struct sockaddr_in *)addr;

	host->localport = laddr->sin_port;
	rte_memcpy(&host->localip, &laddr->sin_addr.s_addr, sizeof (uint32_t));
	rte_memcpy(host->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

	return 0;
}

static ssize_t nrecvfrom(int sockfd, void* buf, size_t len,
				 int flags,
				 struct sockaddr *_src_addr,
				 socklen_t * addrlen) {

	struct localhost *host = get_hostinfo_from_fd(sockfd);
	if (host == NULL) return -1;

	struct offload *ol = NULL;
	int nb = -1;

	pthread_mutex_lock(&host->mutex);
	while ((nb = rte_ring_mc_dequeue(host->rcvbuf, (void **)&ol)) < 0) {
		pthread_cond_wait(&host->cond, &host->mutex);
	}
	pthread_mutex_unlock(&host->mutex);
	
	struct sockaddr_in *saddr = (struct sockaddr_in *)_src_addr;
	saddr->sin_port = ol->sport;
	rte_memcpy(&saddr->sin_addr.s_addr, &ol->sip, sizeof (uint32_t));
	
	if (len < ol->length) {
		rte_memcpy(buf, ol->data, len);
		unsigned char *ptr = rte_malloc("unsigned char *", ol->length - len, 0);
		rte_memcpy(ptr, ol->data + len, ol->length - len);

		ol->length = ol->length - len;
		rte_free(ol->data);
		ol->data = ptr;

		rte_ring_mp_enqueue(host->rcvbuf, ol);
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
			   const struct sockaddr *dest_addr, socklen_t addrlen) {

	struct localhost *host = get_hostinfo_from_fd(sockfd);
	if (host == NULL) return -1;

	struct sockaddr_in *daddr = (struct sockaddr_in *)dest_addr;

	struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
	if (ol == NULL) return -1;

	ol->dip = daddr->sin_addr.s_addr;
	ol->dport = daddr->sin_port;
	ol->sip = host->localip;
	ol->sport = host->localport;
	ol->protocol = IPPROTO_UDP;
	ol->length = len;
	ol->data = rte_malloc("unsigned char *", len, 0);
	if (ol->data == NULL) {
		rte_free(ol);
		return -1;
	}

	rte_memcpy(ol->data, buf, len);

	rte_ring_mp_enqueue(host->sndbuf, ol);
	return len;
}

static int nclose(int fd) {
	struct localhost *host = get_hostinfo_from_fd(fd);
	if (host == NULL) return -1;

	LL_REMOVE(host, lhost);

	if (host->rcvbuf) rte_ring_free(host->rcvbuf);
	if (host->sndbuf) rte_ring_free(host->sndbuf);

	rte_free(host);
	return 0;
}

int udp_server_entry(void *argv) {
	int connfd = nsocket(AF_INET, SOCK_DGRAM, 0);

	if (connfd == -1) {
		printf("socketfd failed\n");
		return -1;
	}

	struct sockaddr_in localaddr, clientaddr;
	memset(&localaddr, 0, sizeof (struct sockaddr_in));

	localaddr.sin_port = htons(8888);
	localaddr.sin_family = AF_INET;
	localaddr.sin_addr.s_addr = inet_addr("192.168.0.120");

	nbind(connfd, (struct sockaddr *)&localaddr, sizeof(struct sockaddr_in));

	char buffer[UDP_APP_RECV_BUFFER_SIZE] = { 0 };
	socklen_t addrlen = sizeof (clientaddr);
	
	while (1) {
		memset(buffer, 0, UDP_APP_RECV_BUFFER_SIZE);
		
		if (nrecvfrom(connfd, buffer, UDP_APP_RECV_BUFFER_SIZE, 0,
			(struct sockaddr *)&clientaddr, &addrlen) < 0) {
			continue;
		} else {
			printf("recv from %s:%d, content: %s\n", inet_ntoa(clientaddr.sin_addr),
				ntohs(clientaddr.sin_port), buffer);

			nsendto(connfd, buffer, strlen(buffer), 0,
				(struct sockaddr *)&clientaddr, sizeof (clientaddr));	
		}
	}

	nclose(connfd);
	return 0;
}
#endif



int main(int argc, char *argv[]) {
    int ret;
    unsigned int lcore_id;

    // 初始化 EAL
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error: Cannot init EAL\n");
    }

    // 创建内存池
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
                                        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Error: Cannot create mbuf pool\n");
    }

    // 初始化端口
    gDpdkPortId = 0;
    ret = init_port(gDpdkPortId);
    if (ret != 0) {
        rte_exit(EXIT_FAILURE, "Error: Cannot init port %u\n", gDpdkPortId);
    }

    // 设置 IP 和端口
	gSrcIp = gLocalIp;
    gSrcPort = rte_cpu_to_be_16(8888);

// 初始化定时器
#if ENABLE_TIMER
	rte_timer_subsystem_init();

	static struct rte_timer arp_timer;
	rte_timer_init(&arp_timer);

	uint64_t hz = rte_get_timer_hz();
	lcore_id = rte_lcore_id();
	printf("Timer setup - hz: %lu, lcore_id: %u\n", hz, lcore_id);
	
	ret = rte_timer_reset(&arp_timer, hz, PERIODICAL, lcore_id, arp_request_timer_cb, mbuf_pool);
	if (ret != 0) {
		printf("Failed to reset timer: %d\n", ret);
	} else {
		printf("Timer reset successfully\n");
	}
#endif

// 初始化 inout ring
#if ENABLE_RINGBUFFER
	struct inout_ring *ring = ring_instance();
	if (ring == NULL) {
		rte_exit(EXIT_FAILURE, "ring buffer init failed");
	}

	if (ring->in == NULL) {
		ring->in = rte_ring_create("in ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	}

	if (ring->out == NULL) {
		ring->out = rte_ring_create("out ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	}
#endif

#if ENABLE_MULTITHREAD
	lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	rte_eal_remote_launch(packet_process, mbuf_pool, lcore_id);
#endif

#if ENABLE_UDP_APP
	lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	rte_eal_remote_launch(udp_server_entry, mbuf_pool, lcore_id);
#endif

    // 主循环：接收和处理数据包
    while (1) {
        struct rte_mbuf *rx[PKT_BURST];
        uint16_t nb_rx = rte_eth_rx_burst(gDpdkPortId, 0, rx, PKT_BURST);
		if (nb_rx > BURST_SIZE) {
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		} else if (nb_rx > 0) {
			rte_ring_sp_enqueue_burst(ring->in, (void **)rx, nb_rx, NULL);
		}

		// tx
		struct rte_mbuf *tx[PKT_BURST];
		unsigned nb_tx = rte_ring_sc_dequeue_burst(ring->out, (void **)tx, BURST_SIZE, NULL);
		if (nb_tx > 0) {
			rte_eth_tx_burst(gDpdkPortId, 0, tx, nb_tx);

			unsigned int i = 0;
			for (i = 0; i < nb_tx; i++) {
				rte_pktmbuf_free(tx[i]);
			}
		}

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

    // 清理
    rte_eth_dev_stop(gDpdkPortId);
    rte_eth_dev_close(gDpdkPortId);
    rte_eal_cleanup();
    return 0;
}
