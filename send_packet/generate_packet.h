#include <rte_memory.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_udp.h>
#include <rte_ip.h>

#define RX_RING_SIZE 1024                                                                                                                    
#define TX_RING_SIZE 1024                                                                                                                      
                                                                                                                                               
#define NUM_MBUFS 8191                                                                                                                         
#define MBUF_CACHE_SIZE 250                                                                                                                    
#define BURST_SIZE 32                                                                                                                          
                                                                                                                                               
#define UDP_SRC_PORT 6666                                                                                                                      
#define UDP_DST_PORT 6666                                                                                                                      
                                                                                                                                               
#define IP_DEFTTL  64   /* from RFC 1340. */                                                                                                  
#define IP_VERSION 0x40                                                                                                                        
#define IP_HDRLEN  0x05 /* default IP header length == five 32-bits words. */                                                                  
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)                                                                                                    
                                                                                                                                               
#define TX_PACKET_LENGTH 862                                                                                                                   
                                                                                                                                               
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN                                                                                                           
#define RTE_BE_TO_CPU_16(be_16_v)  (be_16_v)                                                                                                  
#define RTE_CPU_TO_BE_16(cpu_16_v) (cpu_16_v)                                                                                                  
#else                                                                                                                                          
#define RTE_BE_TO_CPU_16(be_16_v) (uint16_t) ((((be_16_v) & 0xFF) << 8) | ((be_16_v) >> 8))                                                                              
#define RTE_CPU_TO_BE_16(cpu_16_v) (uint16_t) ((((cpu_16_v) & 0xFF) << 8) | ((cpu_16_v) >> 8))                                                                            
#endif                                                                                                                                         
#define RTE_MAX_SEGS_PER_PKT 255
#define MAX_PKTS 256

struct rte_mempool *mbuf_pool;
struct rte_ether_addr my_addr;

uint32_t string_to_ip(char *s) {
    unsigned char a[4];
    int rc = sscanf(s, "%hhd.%hhd.%hhd.%hhd",a+0,a+1,a+2,a+3);
    if(rc != 4){
            fprintf(stderr, "bad source IP address format. Use like: -s 198.19.111.179\n");
            exit(1);
    }

    return
        (uint32_t)(a[0]) << 24 |
        (uint32_t)(a[1]) << 16 |
        (uint32_t)(a[2]) << 8 |
        (uint32_t)(a[3]);
}


uint64_t string_to_mac(char *s) {
    unsigned char a[6];
    int rc = sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                    a + 0, a + 1, a + 2, a + 3, a + 4, a + 5);
    if(rc !=6 ){
    fprintf(stderr, "bad MAC address format. Use like: -m 0a:38:ca:f6:f3:20\n");
    exit(1);
    }

    return
        (uint64_t)(a[0]) << 40 |
        (uint64_t)(a[1]) << 32 |
        (uint64_t)(a[2]) << 24 |
        (uint64_t)(a[3]) << 16 |
        (uint64_t)(a[4]) << 8 |
        (uint64_t)(a[5]);
}

static void setup_pkt_udp_ip_headers(struct rte_ipv4_hdr *ip_hdr,
                         struct rte_udp_hdr *udp_hdr,
                         uint16_t pkt_data_len, uint32_t IP_SRC_ADDR, uint32_t IP_DST_ADDR)
{
        uint16_t *ptr16;
        uint32_t ip_cksum;
        uint16_t pkt_len;

    //Initialize UDP header.
        pkt_len = (uint16_t) (pkt_data_len + sizeof(struct rte_udp_hdr));
        udp_hdr->src_port = rte_cpu_to_be_16(UDP_SRC_PORT);
        udp_hdr->dst_port = rte_cpu_to_be_16(UDP_DST_PORT);
        udp_hdr->dgram_len      = RTE_CPU_TO_BE_16(pkt_len);
        udp_hdr->dgram_cksum    = 0; /* No UDP checksum.*/

    //Initialize IP header.
        pkt_len = (uint16_t) (pkt_len + sizeof(struct rte_ipv4_hdr));
        ip_hdr->version_ihl   = IP_VHL_DEF;
        ip_hdr->type_of_service   = 0;
        ip_hdr->fragment_offset = 0;
        ip_hdr->time_to_live   = IP_DEFTTL;
        ip_hdr->next_proto_id = IPPROTO_UDP;
        ip_hdr->packet_id = 0;
        ip_hdr->total_length   = RTE_CPU_TO_BE_16(pkt_len);
        ip_hdr->src_addr = rte_cpu_to_be_32(IP_SRC_ADDR);
        ip_hdr->dst_addr = rte_cpu_to_be_32(IP_DST_ADDR);

    //Compute IP header checksum.
        ptr16 = (unaligned_uint16_t*) ip_hdr;
        ip_cksum = 0;
        ip_cksum += ptr16[0]; ip_cksum += ptr16[1];
        ip_cksum += ptr16[2]; ip_cksum += ptr16[3];
        ip_cksum += ptr16[4];
        ip_cksum += ptr16[6]; ip_cksum += ptr16[7];
        ip_cksum += ptr16[8]; ip_cksum += ptr16[9];

    //Reduce 32 bit checksum to 16 bits and complement it.
        ip_cksum = ((ip_cksum & 0xFFFF0000) >> 16) +
                (ip_cksum & 0x0000FFFF);
        if (ip_cksum > 65535)
                ip_cksum -= 65535;
        ip_cksum = (~ip_cksum) & 0x0000FFFF;
        if (ip_cksum == 0)
                ip_cksum = 0xFFFF;
        ip_hdr->hdr_checksum = (uint16_t) ip_cksum;
}

static void setup_pkt_headers(struct rte_ipv4_hdr *ip_hdr, struct rte_udp_hdr *udp_hdr, uint16_t pkt_data_len, char *mac_addr, char *src_addr, char *dst_addr){
    if(src_addr == NULL || dst_addr == NULL || mac_addr == NULL) {
        printf("Please setup mac_addr, source address, destination address\n");
        return;
    }
    uint32_t DST_MAC = 0ULL, IP_SRC_ADDR = 0ULL, IP_DST_ADDR = 0ULL;
    DST_MAC = string_to_mac(mac_addr);
    IP_SRC_ADDR = string_to_ip(src_addr);
    IP_DST_ADDR = string_to_ip(dst_addr);

    setup_pkt_udp_ip_headers(ip_hdr, udp_hdr, pkt_data_len, IP_SRC_ADDR, IP_DST_ADDR);
}

static void
copy_buf_to_pkt_segs(void *buf, unsigned len, struct rte_mbuf *pkt,
        unsigned offset)
{
    struct rte_mbuf *seg;
    void *seg_buf;
    unsigned copy_len;

    seg = pkt;
    // 여러개의 segment를 보낼 때를 대비하여 offset에서 seg->data_len을 빼주면서
    // 연결된 segment로 이동한다.
    while (offset >= seg->data_len) {
        offset -= seg->data_len;
        seg = seg->next;
    }
    copy_len = seg->data_len - offset;
    seg_buf = rte_pktmbuf_mtod_offset(seg, char *, offset);
    while (len > copy_len) {
        rte_memcpy(seg_buf, buf, (size_t) copy_len);
        len -= copy_len;
        buf = ((char *) buf + copy_len);
        //seg = seg->next로 계속 옮기면서 저장한다.
        seg = seg->next;
        seg_buf = rte_pktmbuf_mtod(seg, void *);
    }
    // seg_buf <- buf를 copy한다.
    rte_memcpy(seg_buf, buf, (size_t) len);
}

static inline void
copy_buf_to_pkt(void *buf, unsigned len, struct rte_mbuf *pkt, unsigned offset)
{
    if (offset + len <= pkt->data_len) {
        rte_memcpy(rte_pktmbuf_mtod_offset(pkt, char *, offset), buf,
               (size_t) len);
        return;
    }
    copy_buf_to_pkt_segs(buf, len, pkt, offset);
}

static int port_init(uint16_t port){
    struct rte_eth_conf port_conf = {
        .rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN }
    };
    const uint16_t rx_rings = 0, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if(!rte_eth_dev_is_valid_port(port)) return -1;

    rte_eth_dev_info_get(port, &dev_info);
    if(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;

    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if(retval) return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if(retval) return retval;

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;

    for (int q = 0 ; q < tx_rings ; q++){
        retval = rte_eth_tx_queue_setup(port, q, nb_txd, rte_eth_dev_socket_id(port), &txconf);
        if(retval < 0) return retval;
    }

    retval = rte_eth_dev_start(port);
    if (retval < 0) return retval;

    rte_eth_macaddr_get(port, &my_addr);
}

void setup_eal(int argc, char *argv[]){
    int ret;
    ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_panic("Cannot init\n");
    argc -= ret;
    argv += ret;

    if(mbuf_pool) return;
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if(mbuf_pool == NULL) rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n"); 
    
    int nb_ports = rte_eth_dev_count_avail(), portid;
    RTE_ETH_FOREACH_DEV(portid)
        if(port_init(portid) != 0)
            rte_exit(EXIT_FAILURE, "Cannot Init port \n");
}

int send_packet(char *mac_addr, char *src_addr, char *dst_addr, char *data){
    int ret, c;
    uint16_t pkt_data_len;
    
    struct rte_ipv4_hdr ip_hdr;
    struct rte_udp_hdr udp_hdr;
    uint16_t nb_pkt_segs = 1;
    size_t eth_hdr_size;
    uint32_t pkt_len = sizeof(data);
    bool vlan_enabled = false, ipv4 = true;

    setup_pkt_headers(&ip_hdr, &udp_hdr, 862, mac_addr, src_addr, dst_addr);

    struct rte_mbuf *pkts_burst[MAX_PKTS];
    struct rte_mbuf *pkt, *pkt_seg;

    pkt = rte_pktmbuf_alloc(mbuf_pool);
    pkt->data_len = pkt_len;
    pkt_seg = pkt;

    for(int i = 1 ; i < nb_pkt_segs ; i++){
        pkt_seg->next = rte_pktmbuf_alloc(mbuf_pool);
        if(pkt_seg->next == NULL){
            pkt->nb_segs = i;
            rte_pktmbuf_free(pkt);
            goto nomore_mbuf;
        }
        pkt_seg = pkt_seg->next;
        pkt_seg->data_len = pkt_len;
    }
    pkt_seg->next = NULL;
    
    if(vlan_enabled)
        eth_hdr_size = sizeof(struct rte_ether_hdr) + sizeof(struct rte_vlan_hdr);
    else
        eth_hdr_size = sizeof(struct rte_ether_hdr);

    copy_buf_to_pkt(&my_addr, eth_hdr_size, pkt, 0);
    if(ipv4){
        copy_buf_to_pkt(&ip_hdr, sizeof(struct rte_ipv4_hdr), pkt, eth_hdr_size);
        copy_buf_to_pkt(&udp_hdr, sizeof(struct rte_udp_hdr), pkt, eth_hdr_size + sizeof(struct rte_ipv4_hdr));
        copy_buf_to_pkt(data, sizeof(data), pkt, eth_hdr_size + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr));
    }
    else{
        copy_buf_to_pkt(&ip_hdr, sizeof(struct rte_ipv6_hdr), pkt, eth_hdr_size);
        copy_buf_to_pkt(&udp_hdr, sizeof(struct rte_udp_hdr), pkt, eth_hdr_size + sizeof(struct rte_ipv6_hdr));
        copy_buf_to_pkt(data, sizeof(data), pkt, eth_hdr_size + sizeof(struct rte_ipv6_hdr) + sizeof(struct rte_udp_hdr));
    }

    pkt->nb_segs = nb_pkt_segs;
    pkt->pkt_len = pkt_len;
    pkt->l2_len = eth_hdr_size;

    if (ipv4) {
        pkt->vlan_tci  = RTE_ETHER_TYPE_IPV4;
        pkt->l3_len = sizeof(struct rte_ipv4_hdr);
    } else {
        pkt->vlan_tci  = RTE_ETHER_TYPE_IPV6;
        pkt->l3_len = sizeof(struct rte_ipv6_hdr);
    }

    pkts_burst[0] = pkt;

    uint16_t nb_tx = rte_eth_tx_burst(0, 0, pkts_burst, 1);
    rte_mbuf_raw_free(pkts_burst[0]);

    return 0;
nomore_mbuf:
            return -1;
}

































