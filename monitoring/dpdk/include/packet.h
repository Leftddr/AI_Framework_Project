#define RTE_ETHER_ADDR_LEN  6
#define __rte_aligned(a) __attribute__((__aligned__(a)))
#define __rte_packed __attribute__((__packed__))
#define rte_pktmbuf_mtod_offset(m, t, o)    \
    ((t)((char *)(m)->buf_addr + (m)->data_off + (o)))

typedef uint16_t rte_be16_t; /**< 16-bit big-endian value. */
typedef uint32_t rte_be32_t; /**< 32-bit big-endian value. */
typedef uint64_t rte_be64_t; /**< 64-bit big-endian value. */
typedef uint16_t rte_le16_t; /**< 16-bit little-endian value. */
typedef uint32_t rte_le32_t; /**< 32-bit little-endian value. */
typedef uint64_t rte_le64_t; /**< 64-bit little-endian value. */

struct rte_ether_addr {
    uint8_t addr_bytes[RTE_ETHER_ADDR_LEN]; /**< Addr bytes in tx order */
} __rte_aligned(2);

struct rte_ether_hdr {
    struct rte_ether_addr d_addr; /**< Destination address. */
    struct rte_ether_addr s_addr; /**< Source address. */
    uint16_t ether_type;      /**< Frame type. */
} __rte_aligned(2);

__extension__
struct rte_ipv4_hdr {
    union {
        uint8_t version_ihl;    /**< version and header length */
        struct {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
            uint8_t ihl:4;
            uint8_t version:4;
#elif RTE_BYTE_ORDER == RTE_BIG_ENDIAN
            uint8_t version:4;
            uint8_t ihl:4;
#else
#error "setup endian definition"
#endif
        };
    };
    uint8_t  type_of_service;   /**< type of service */
    rte_be16_t total_length;    /**< length of packet */
    rte_be16_t packet_id;       /**< packet ID */
    rte_be16_t fragment_offset; /**< fragmentation offset */
    uint8_t  time_to_live;      /**< time to live */
    uint8_t  next_proto_id;     /**< protocol ID */
    rte_be16_t hdr_checksum;    /**< header checksum */
    rte_be32_t src_addr;        /**< source address */
    rte_be32_t dst_addr;        /**< destination address */
} __rte_packed;

struct rte_udp_hdr {
    rte_be16_t src_port;    /**< UDP source port. */
    rte_be16_t dst_port;    /**< UDP destination port. */
    rte_be16_t dgram_len;   /**< UDP datagram length */
    rte_be16_t dgram_cksum; /**< UDP datagram checksum */
} __rte_packed;

static inline void *
rte_memcpy(void *dst, const void *src, size_t n)
{
    return memcpy(dst, src, n);
}

