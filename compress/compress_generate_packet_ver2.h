/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>

#include <rte_malloc.h>
#include <rte_eal.h>
#include <rte_log.h>
#include <rte_compressdev.h>

#include "generate_packet.h"

#ifndef _COMP_PERF_OPS_
#define _COMP_PERF_OPS_
#endif

#define MAX_LIST        32
#define MIN_COMPRESSED_BUF_SIZE 8
#define EXPANSE_RATIO 1.1
#define MAX_MBUF_DATA_SIZE (UINT16_MAX - RTE_PKTMBUF_HEADROOM)
#define MAX_SEG_SIZE ((int)(MAX_MBUF_DATA_SIZE / EXPANSE_RATIO))

#define NUM_MAX_XFORMS 16
#define NUM_MAX_INFLIGHT_OPS 512
#define SEND_CNT 256

#define DIV_CEIL(a, b)  ((a) / (b) + ((a) % (b) != 0))

#define CPERF_PTEST_TYPE    ("ptest")
#define CPERF_SILENT        ("silent")

#define CPERF_POOL_SIZE     ("pool-sz")
#define CPERF_TOTAL_OPS     ("total-ops")
#define CPERF_BURST_SIZE    ("burst-sz")
#define CPERF_BUFFER_SIZE   ("buffer-sz")
#define CPERF_SEGMENT_SIZE  ("segment-sz")
#define CPERF_DESC_NB       ("desc-nb")
#define CPERF_IMIX      ("imix")

#define CPERF_DEVTYPE       ("devtype")
#define CPERF_OPTYPE        ("optype")
#define CPERF_SESSIONLESS   ("sessionless")
#define CPERF_OUT_OF_PLACE  ("out-of-place")
#define CPERF_TEST_FILE     ("test-file")
#define CPERF_TEST_NAME     ("test-name")

#define CPERF_CIPHER_ALGO   ("cipher-algo")
#define CPERF_CIPHER_OP     ("cipher-op")
#define CPERF_CIPHER_KEY_SZ ("cipher-key-sz")
#define CPERF_CIPHER_IV_SZ  ("cipher-iv-sz")

#define CPERF_AUTH_ALGO     ("auth-algo")
#define CPERF_AUTH_OP       ("auth-op")
#define CPERF_AUTH_KEY_SZ   ("auth-key-sz")
#define CPERF_AUTH_IV_SZ    ("auth-iv-sz")

#define CPERF_AEAD_ALGO     ("aead-algo")
#define CPERF_AEAD_OP       ("aead-op")
#define CPERF_AEAD_KEY_SZ   ("aead-key-sz")
#define CPERF_AEAD_IV_SZ    ("aead-iv-sz")
#define CPERF_AEAD_AAD_SZ   ("aead-aad-sz")

#define CPERF_DIGEST_SZ     ("digest-sz")

#ifdef RTE_LIB_SECURITY
#define CPERF_PDCP_SN_SZ    ("pdcp-sn-sz")
#define CPERF_PDCP_DOMAIN   ("pdcp-domain")
#define CPERF_PDCP_SES_HFN_EN   ("pdcp-ses-hfn-en")
#define PDCP_DEFAULT_HFN    0x1
#define CPERF_DOCSIS_HDR_SZ ("docsis-hdr-sz")
#endif

#define CPERF_CSV       ("csv-friendly")

/* benchmark-specific options */
#define CPERF_PMDCC_DELAY_MS    ("pmd-cyclecount-delay-ms")

#define MAX_LIST 32

#define CPERF_PTEST_TYPE    ("ptest")
#define CPERF_DRIVER_NAME   ("driver-name")
#define CPERF_SEG_SIZE      ("seg-sz")
#define CPERF_BURST_SIZE    ("burst-sz")
#define CPERF_EXTENDED_SIZE ("extended-input-sz")
#define CPERF_POOL_SIZE     ("pool-sz")
#define CPERF_MAX_SGL_SEGS  ("max-num-sgl-segs")
#define CPERF_NUM_ITER      ("num-iter")
#define CPERF_HUFFMAN_ENC   ("huffman-enc")
#define CPERF_LEVEL     ("compress-level")
#define CPERF_WINDOW_SIZE   ("window-sz")
#define CPERF_EXTERNAL_MBUFS    ("external-mbufs")

enum comp_operation {
    COMPRESS_ONLY,
    DECOMPRESS_ONLY,
    COMPRESS_DECOMPRESS
};

enum cleanup_st {
    ST_CLEAR = 0,
    ST_TEST_DATA,
    ST_COMPDEV,
    ST_INPUT_DATA,
    ST_MEMORY_ALLOC,
    ST_DURING_TEST
};

enum cperf_test_type {
    CPERF_TEST_TYPE_THROUGHPUT,
    CPERF_TEST_TYPE_VERIFY,
    CPERF_TEST_TYPE_PMDCC
};

struct range_list {
    uint8_t min;
    uint8_t max;
    uint8_t inc;
    uint8_t count;
    uint8_t list[MAX_LIST];
};

struct cperf_mem_resources {
    uint8_t dev_id;
    uint16_t qp_id;
    uint8_t lcore_id;

    rte_atomic16_t print_info_once;

    uint32_t total_bufs;
    uint8_t *compressed_data;
    uint8_t *decompressed_data;

    struct rte_mbuf **comp_bufs;
    struct rte_mbuf **decomp_bufs;

    struct rte_mempool *comp_buf_pool;
    struct rte_mempool *decomp_buf_pool;
    struct rte_mempool *op_pool;

    /* external mbuf support */
    const struct rte_memzone **comp_memzones;
    const struct rte_memzone **decomp_memzones;
    struct rte_mbuf_ext_shared_info *comp_buf_infos;
    struct rte_mbuf_ext_shared_info *decomp_buf_infos;
};

struct comp_test_data {
    char driver_name[RTE_DEV_NAME_MAX_LEN];
    char input_file[PATH_MAX];
    // specify option i use
    enum cperf_test_type test;

    uint8_t *input_data;
    size_t input_data_sz;
    uint16_t nb_qps;
    uint16_t seg_sz;
    uint16_t out_seg_sz;
    uint16_t burst_sz;
    uint32_t pool_sz;
    uint32_t num_iter;
    uint16_t max_sgl_segs;
    uint32_t total_segs;

    enum rte_comp_huffman huffman_enc;
    enum comp_operation test_op;
    int window_sz;
    struct range_list level_lst;
    uint8_t level;
    int use_external_mbufs;

    double ratio;
    enum cleanup_st cleanup;
    int perf_comp_force_stop;

    uint32_t cyclecount_delay;
};

static struct comp_test_data *test_data;

struct cperf_verify_ctx {
    struct cperf_mem_resources mem;
    struct comp_test_data *options;

    int silent;
    size_t comp_data_sz;
    size_t decomp_data_sz;
    double ratio;
};

struct cperf_benchmark_ctx {
    struct cperf_verify_ctx ver;

    /* Store TSC duration for all levels (including level 0) */
    uint64_t comp_tsc_duration[RTE_COMP_LEVEL_MAX + 1];
    uint64_t decomp_tsc_duration[RTE_COMP_LEVEL_MAX + 1];
    double comp_gbps;
    double decomp_gbps;
    double comp_tsc_byte;
    double decomp_tsc_byte;
};

struct cperf_benchmark_ctx *gctx;

struct cperf_buffer_info {
    uint16_t total_segments;
    uint16_t segment_sz;
    uint16_t last_segment_sz;
    uint32_t total_buffs;         /*number of buffers = number of ops*/
    uint16_t segments_per_buff;
    uint16_t segments_per_last_buff;
    size_t input_data_sz;
};

static struct cperf_buffer_info buffer_info;

static void
comp_perf_extbuf_free_cb(void *addr __rte_unused, void *opaque __rte_unused)
{
}

static void
usage(char *progname)
{
    printf("%s [EAL options] --\n"
        " --driver-name NAME: compress driver to use\n",
        progname);
}

void
comp_perf_free_memory(struct comp_test_data *test_data,
              struct cperf_mem_resources *mem)
{
    uint32_t i;

    if (mem->decomp_bufs != NULL)
        for (i = 0; i < mem->total_bufs; i++)
            rte_pktmbuf_free(mem->decomp_bufs[i]);

    if (mem->comp_bufs != NULL)
        for (i = 0; i < mem->total_bufs; i++)
            rte_pktmbuf_free(mem->comp_bufs[i]);

    rte_free(mem->decomp_bufs);
    rte_free(mem->comp_bufs);
    rte_free(mem->decompressed_data);
    rte_free(mem->compressed_data);
    rte_mempool_free(mem->op_pool);
    rte_mempool_free(mem->decomp_buf_pool);
    rte_mempool_free(mem->comp_buf_pool);

    /* external mbuf support */
    if (mem->decomp_memzones != NULL) {
        for (i = 0; i < test_data->total_segs; i++)
            rte_memzone_free(mem->decomp_memzones[i]);
        rte_free(mem->decomp_memzones);
    }
    if (mem->comp_memzones != NULL) {
        for (i = 0; i < test_data->total_segs; i++)
            rte_memzone_free(mem->comp_memzones[i]);
        rte_free(mem->comp_memzones);
    }
    rte_free(mem->decomp_buf_infos);
    rte_free(mem->comp_buf_infos);
}

void
compress_destructor(void *arg)
{
	if (arg) {
		comp_perf_free_memory(
			((struct cperf_benchmark_ctx *)arg)->ver.options,
			&((struct cperf_benchmark_ctx *)arg)->ver.mem);
		rte_free(arg);
	}
}

const struct rte_memzone *
comp_perf_make_memzone(const char *name, struct cperf_mem_resources *mem,
               unsigned int number, size_t size)
{
    unsigned int socket_id = rte_socket_id();
    char mz_name[RTE_MEMZONE_NAMESIZE];
    const struct rte_memzone *memzone;

    snprintf(mz_name, RTE_MEMZONE_NAMESIZE, "%s_s%u_d%u_q%u_%d", name,
         socket_id, mem->dev_id, mem->qp_id, number);
    memzone = rte_memzone_lookup(mz_name);
    if (memzone != NULL && memzone->len != size) {
        rte_memzone_free(memzone);
        memzone = NULL;
    }
    if (memzone == NULL) {
        memzone = rte_memzone_reserve_aligned(mz_name, size, socket_id,
                RTE_MEMZONE_IOVA_CONTIG, RTE_CACHE_LINE_SIZE);
        if (memzone == NULL)
            RTE_LOG(ERR, USER1, "Can't allocate memory zone %s\n",
                mz_name);
    }
    return memzone;
}

int
comp_perf_allocate_external_mbufs(struct comp_test_data *test_data,
                  struct cperf_mem_resources *mem)
{
    uint32_t i;

    mem->comp_memzones = rte_zmalloc_socket(NULL,
        test_data->total_segs * sizeof(struct rte_memzone *),
        0, rte_socket_id());

    if (mem->comp_memzones == NULL) {
        RTE_LOG(ERR, USER1,
            "Memory to hold the compression memzones could not be allocated\n");
        return -1;
    }

    mem->decomp_memzones = rte_zmalloc_socket(NULL,
        test_data->total_segs * sizeof(struct rte_memzone *),
        0, rte_socket_id());

    if (mem->decomp_memzones == NULL) {
        RTE_LOG(ERR, USER1,
            "Memory to hold the decompression memzones could not be allocated\n");
        return -1;
    }

    mem->comp_buf_infos = rte_zmalloc_socket(NULL,
        test_data->total_segs * sizeof(struct rte_mbuf_ext_shared_info),
        0, rte_socket_id());

    if (mem->comp_buf_infos == NULL) {
        RTE_LOG(ERR, USER1,
            "Memory to hold the compression buf infos could not be allocated\n");
        return -1;
    }

    mem->decomp_buf_infos = rte_zmalloc_socket(NULL,
        test_data->total_segs * sizeof(struct rte_mbuf_ext_shared_info),
        0, rte_socket_id());

    if (mem->decomp_buf_infos == NULL) {
        RTE_LOG(ERR, USER1,
            "Memory to hold the decompression buf infos could not be allocated\n");
        return -1;
    }

    for (i = 0; i < test_data->total_segs; i++) {
        mem->comp_memzones[i] = comp_perf_make_memzone("comp", mem,
                i, test_data->out_seg_sz);
        if (mem->comp_memzones[i] == NULL) {
            RTE_LOG(ERR, USER1,
                "Memory to hold the compression memzone could not be allocated\n");
            return -1;
    }

    mem->decomp_buf_infos = rte_zmalloc_socket(NULL,
        test_data->total_segs * sizeof(struct rte_mbuf_ext_shared_info),
        0, rte_socket_id());

    if (mem->decomp_buf_infos == NULL) {
        RTE_LOG(ERR, USER1,
            "Memory to hold the decompression buf infos could not be allocated\n");
        return -1;
    }

    for (i = 0; i < test_data->total_segs; i++) {
        mem->comp_memzones[i] = comp_perf_make_memzone("comp", mem,
                i, test_data->out_seg_sz);
        if (mem->comp_memzones[i] == NULL) {
            RTE_LOG(ERR, USER1,
                "Memory to hold the compression memzone could not be allocated\n");
            return -1;
        }

        mem->decomp_memzones[i] = comp_perf_make_memzone("decomp", mem,
                i, test_data->seg_sz);
        if (mem->decomp_memzones[i] == NULL) {
            RTE_LOG(ERR, USER1,
                "Memory to hold the decompression memzone could not be allocated\n");
            return -1;
        }

        mem->comp_buf_infos[i].free_cb =
                comp_perf_extbuf_free_cb;
        mem->comp_buf_infos[i].fcb_opaque = NULL;
        rte_mbuf_ext_refcnt_set(&mem->comp_buf_infos[i], 1);

        mem->decomp_buf_infos[i].free_cb =
                comp_perf_extbuf_free_cb;
        mem->decomp_buf_infos[i].fcb_opaque = NULL;
        rte_mbuf_ext_refcnt_set(&mem->decomp_buf_infos[i], 1);
    }

    return 0;
    }
}

uint32_t
find_buf_size(uint32_t input_size)
{
    uint32_t i;

    /* From performance point of view the buffer size should be a
     * power of 2 but also should be enough to store incompressible data
     */

    /* We're looking for nearest power of 2 buffer size, which is greater
     * than input_size
     */
    uint32_t size =
        !input_size ? MIN_COMPRESSED_BUF_SIZE : (input_size << 1);

    for (i = UINT16_MAX + 1; !(i & size); i >>= 1)
        ;

    return i > ((UINT16_MAX + 1) >> 1)
            ? (uint32_t)((float)input_size * EXPANSE_RATIO)
            : i;
}

int
comp_perf_allocate_memory(struct comp_test_data *test_data,
              struct cperf_mem_resources *mem)
{
    uint16_t comp_mbuf_size;
    uint16_t decomp_mbuf_size;

    test_data->out_seg_sz = find_buf_size(test_data->seg_sz);

    /* Number of segments for input and output
     * (compression and decompression)
     */
    test_data->total_segs = DIV_CEIL(test_data->input_data_sz,
            test_data->seg_sz);

    if (test_data->use_external_mbufs != 0) {
        if (comp_perf_allocate_external_mbufs(test_data, mem) < 0)
            return -1;
        comp_mbuf_size = 0;
        decomp_mbuf_size = 0;
    } else {
        comp_mbuf_size = test_data->out_seg_sz + RTE_PKTMBUF_HEADROOM;
        decomp_mbuf_size = test_data->seg_sz + RTE_PKTMBUF_HEADROOM;
    }

    char pool_name[32] = "";

    snprintf(pool_name, sizeof(pool_name), "comp_buf_pool_%u_qp_%u",
            mem->dev_id, mem->qp_id);
    // Make Memory pool to compress.
    mem->comp_buf_pool = rte_pktmbuf_pool_create(pool_name,
                test_data->total_segs,
                0, 0,
                comp_mbuf_size,
                rte_socket_id());
    if (mem->comp_buf_pool == NULL) {
        RTE_LOG(ERR, USER1, "Mbuf mempool could not be created\n");
        return -1;
    }

    snprintf(pool_name, sizeof(pool_name), "decomp_buf_pool_%u_qp_%u",
            mem->dev_id, mem->qp_id);
    // Make Memory pool to decompress.
    mem->decomp_buf_pool = rte_pktmbuf_pool_create(pool_name,
                test_data->total_segs,
                0, 0,
                decomp_mbuf_size,
                rte_socket_id());
    if (mem->decomp_buf_pool == NULL) {
        RTE_LOG(ERR, USER1, "Mbuf mempool could not be created\n");
        return -1;
    }

    mem->total_bufs = DIV_CEIL(test_data->total_segs,
                   test_data->max_sgl_segs);

    snprintf(pool_name, sizeof(pool_name), "op_pool_%u_qp_%u",
            mem->dev_id, mem->qp_id);

    /* one mempool for both src and dst mbufs */
    /* Make memory pool to use for decompress operation. */
    mem->op_pool = rte_comp_op_pool_create(pool_name,
                mem->total_bufs * 2,
                0, 0, rte_socket_id());
    if (mem->op_pool == NULL) {
        RTE_LOG(ERR, USER1, "Comp op mempool could not be created\n");
        return -1;
    }

    /*
     * Compressed data might be a bit larger than input data,
     * if data cannot be compressed
     */
    /* Make Memory to use for compressed data. */
    mem->compressed_data = rte_zmalloc_socket(NULL,
                RTE_MAX(
                    (size_t) test_data->out_seg_sz *
                              test_data->total_segs,
                    (size_t) MIN_COMPRESSED_BUF_SIZE),
                0,
                rte_socket_id());
    if (mem->compressed_data == NULL) {
        RTE_LOG(ERR, USER1, "Memory to hold the data from the input "
                "file could not be allocated\n");
        return -1;
    }
    /* Make Memory to use for decompressed data. */
    mem->decompressed_data = rte_zmalloc_socket(NULL,
                test_data->input_data_sz, 0,
                rte_socket_id());
    if (mem->decompressed_data == NULL) {
        RTE_LOG(ERR, USER1, "Memory to hold the data from the input "
                "file could not be allocated\n");
        return -1;
    }
    /* Make for compressed packet. */
    mem->comp_bufs = rte_zmalloc_socket(NULL,
            mem->total_bufs * sizeof(struct rte_mbuf *),
            0, rte_socket_id());
    if (mem->comp_bufs == NULL) {
        RTE_LOG(ERR, USER1, "Memory to hold the compression mbufs"
                " could not be allocated\n");
        return -1;
    }
    /* Make for decompressed packet. */
    mem->decomp_bufs = rte_zmalloc_socket(NULL,
            mem->total_bufs * sizeof(struct rte_mbuf *),
            0, rte_socket_id());
    if (mem->decomp_bufs == NULL) {
        RTE_LOG(ERR, USER1, "Memory to hold the decompression mbufs"
                " could not be allocated\n");
        return -1;
    }

    buffer_info.total_segments = test_data->total_segs;
    buffer_info.segment_sz = test_data->seg_sz;
    buffer_info.total_buffs = mem->total_bufs;
    buffer_info.segments_per_buff = test_data->max_sgl_segs;
    buffer_info.input_data_sz = test_data->input_data_sz;

    return 0;
}

void *
compress_constructor(uint8_t dev_id, uint16_t qp_id,
		struct comp_test_data *options)
{
	struct cperf_benchmark_ctx *ctx = NULL;

	ctx = rte_malloc(NULL, sizeof(struct cperf_benchmark_ctx), 0);

	if (ctx == NULL)
		return NULL;

	ctx->ver.mem.dev_id = dev_id;
	ctx->ver.mem.qp_id = qp_id;
	ctx->ver.options = options;
	ctx->ver.silent = 1; /* ver. part will be silent */

	if (!comp_perf_allocate_memory(ctx->ver.options, &ctx->ver.mem)){
        gctx = ctx;
		return ctx;
    }

	compress_destructor(ctx);
	return NULL;
}

int
main_loop(struct cperf_benchmark_ctx *ctx, enum rte_comp_xform_type type, char *mac_addr, char *src_addr, char *dst_addr, char *data)
{
	struct comp_test_data *test_data = ctx->ver.options;
	struct cperf_mem_resources *mem = &ctx->ver.mem;
	uint8_t dev_id = mem->dev_id;
	uint32_t i, iter, num_iter;
	struct rte_comp_op **ops, **deq_ops;
	void *priv_xform = NULL;
	struct rte_comp_xform xform;
	struct rte_mbuf **input_bufs, **output_bufs;
	int res = 0;
	int allocated = 0;
	uint32_t out_seg_sz;

	if (test_data == NULL || !test_data->burst_sz) {
		RTE_LOG(ERR, USER1,
			"Unknown burst size\n");
		return -1;
	}

	ops = rte_zmalloc_socket(NULL,
		2 * mem->total_bufs * sizeof(struct rte_comp_op *),
		0, rte_socket_id());

	if (ops == NULL) {
		RTE_LOG(ERR, USER1,
			"Can't allocate memory for ops strucures\n");
		return -1;
	}

	deq_ops = &ops[mem->total_bufs];

	if (type == RTE_COMP_COMPRESS) {
		xform = (struct rte_comp_xform) {
			.type = RTE_COMP_COMPRESS,
			.compress = {
				.algo = RTE_COMP_ALGO_DEFLATE,
				.deflate.huffman = test_data->huffman_enc,
				.level = test_data->level,
				.window_size = test_data->window_sz,
				.chksum = RTE_COMP_CHECKSUM_NONE,
				.hash_algo = RTE_COMP_HASH_ALGO_NONE
			}
		};
		input_bufs = mem->decomp_bufs;
		output_bufs = mem->comp_bufs;
		out_seg_sz = test_data->out_seg_sz;
	} else {
		xform = (struct rte_comp_xform) {
			.type = RTE_COMP_DECOMPRESS,
			.decompress = {
				.algo = RTE_COMP_ALGO_DEFLATE,
				.chksum = RTE_COMP_CHECKSUM_NONE,
				.window_size = test_data->window_sz,
				.hash_algo = RTE_COMP_HASH_ALGO_NONE
			}
		};
		input_bufs = mem->comp_bufs;
		output_bufs = mem->decomp_bufs;
		out_seg_sz = test_data->seg_sz;
	}

	/* Create private xform */
	if (rte_compressdev_private_xform_create(dev_id, &xform,
			&priv_xform) < 0) {
		RTE_LOG(ERR, USER1, "Private xform could not be created\n");
		res = -1;
		goto end;
	}

	uint64_t tsc_start, tsc_end, tsc_duration;

	num_iter = test_data->num_iter;
	tsc_start = tsc_end = tsc_duration = 0;
	tsc_start = rte_rdtsc_precise();
	uint16_t num_enq = 0;
	uint16_t num_deq = 0;
	uint32_t total_ops = 0;
 	struct rte_mbuf *pkt = compress_make_packet(mem->comp_buf_pool, mac_addr, src_addr, dst_addr, data);
    struct rte_mbuf *output_pkt;
    int tx_count = 1;
    //RESET ALL DATA
	ops[0]->m_src = pkt;
	ops[0]->m_dst = output_pkt;
	ops[0]->src.offset = 0;
	ops[0]->src.length =
	ops[0]->dst.offset = 0;
	ops[0]->flush_flag = RTE_COMP_FLUSH_FINAL;
	ops[0]->input_chksum = 0;
	ops[0]->private_xform = priv_xform;
	if(unlikely(test_data->perf_comp_force_stop)) goto end;
	// enqueue packet to be compressed
	num_enq = rte_compressdev_enqueue_burst(dev_id, mem->qp_id, ops, tx_count);
	i = 0;
    struct rte_mbuf *pkts_burst[SEND_CNT];
    while(total_ops < num_enq){
		// dequeue compressed packet.
 		num_deq = rte_compressdev_dequeue_burst(dev_id, mem->qp_id, deq_ops, tx_count);
		total_ops += num_deq;
		struct rte_mbuf *pkts_burst[SEND_CNT];
		for(i = 0 ; i < num_deq ; i++){
			struct rte_comp_op *op = deq_ops[i];
			if(op->status != RTE_COMP_OP_STATUS_SUCCESS) {
				RTE_LOG(ERR, USER1, "Some operations were not successful\n");
				goto end;
			}
			struct rte_mbuf *m = op->m_dst;
			m->pkt_len = op->produced;
			uint32_t remaining_data = op->produced;
			uint16_t data_to_append;
			while(remaining_data > 0){
				data_to_append = RTE_MIN(remaining_data, out_seg_sz);
				m->data_len = data_to_append;
				remaining_data -= data_to_append;
				m = m->next;
			}
			pkts_burst[i] = m;
		}
		uint32_t nb_tx = rte_eth_tx_burst(0, 0, pkts_burst, num_deq);
	}
	for(i = 0 ; i < tx_count ; i++) if(pkts_burst[i] != NULL) {
		rte_pktmbuf_free(pkts_burst[i]);
	}
end:
	rte_mempool_put_bulk(mem->op_pool, (void **)ops, allocated);
	rte_compressdev_private_xform_free(dev_id, priv_xform);
	rte_free(ops);

	if (test_data->perf_comp_force_stop) {
		RTE_LOG(ERR, USER1,
		      "lcore: %d Perf. test has been aborted by user\n",
			mem->lcore_id);
		res = -1;
	}
	return res;
}
/* user must use this main_loop function */
void send_compress_packet(char *mac_addr, char *src_addr, char *dst_addr, char *data){
    main_loop(gctx, RTE_COMP_COMPRESS, mac_addr, src_addr, dst_addr, data);
}

int
param_range_check(uint16_t size, const struct rte_param_log2_range *range)
{
    unsigned int next_size;

    /* Check lower/upper bounds */
    if (size < range->min)
        return -1;

    if (size > range->max)
        return -1;

    /* If range is actually only one value, size is correct */
    if (range->increment == 0)
        return 0;

    /* Check if value is one of the supported sizes */
    for (next_size = range->min; next_size <= range->max;
            next_size += range->increment)
        if (size == next_size)
            return 0;

    return -1;
}

int
comp_perf_check_capabilities(struct comp_test_data *test_data, uint8_t cdev_id)
{
	const struct rte_compressdev_capabilities *cap;

	cap = rte_compressdev_capability_get(cdev_id,
					     RTE_COMP_ALGO_DEFLATE);

	if (cap == NULL) {
		RTE_LOG(ERR, USER1,
			"Compress device does not support DEFLATE\n");
		return -1;
	}

	uint64_t comp_flags = cap->comp_feature_flags;

	/* Huffman enconding */
	if (test_data->huffman_enc == RTE_COMP_HUFFMAN_FIXED &&
			(comp_flags & RTE_COMP_FF_HUFFMAN_FIXED) == 0) {
		RTE_LOG(ERR, USER1,
			"Compress device does not supported Fixed Huffman\n");
		return -1;
	}

	if (test_data->huffman_enc == RTE_COMP_HUFFMAN_DYNAMIC &&
			(comp_flags & RTE_COMP_FF_HUFFMAN_DYNAMIC) == 0) {
		RTE_LOG(ERR, USER1,
			"Compress device does not supported Dynamic Huffman\n");
		return -1;
	}

	/* Window size */
	if (test_data->window_sz != -1) {
		if (param_range_check(test_data->window_sz, &cap->window_size)
				< 0) {
			RTE_LOG(ERR, USER1,
				"Compress device does not support "
				"this window size\n");
			return -1;
		}
	} else
		/* Set window size to PMD maximum if none was specified */
		test_data->window_sz = cap->window_size.max;

	/* Check if chained mbufs is supported */
	if (test_data->max_sgl_segs > 1  &&
			(comp_flags & RTE_COMP_FF_OOP_SGL_IN_SGL_OUT) == 0) {
		RTE_LOG(INFO, USER1, "Compress device does not support "
				"chained mbufs. Max SGL segments set to 1\n");
		test_data->max_sgl_segs = 1;
	}

	/* Level 0 support */
	if (test_data->level_lst.min == 0 &&
			(comp_flags & RTE_COMP_FF_NONCOMPRESSED_BLOCKS) == 0) {
		RTE_LOG(ERR, USER1, "Compress device does not support "
				"level 0 (no compression)\n");
		return -1;
	}

	return 0;
}

int
comp_perf_initialize_compressdev(struct comp_test_data *test_data,
				 uint8_t *enabled_cdevs)
{
	uint8_t enabled_cdev_count, nb_lcores, cdev_id;
	unsigned int i, j;
	int ret;

	enabled_cdev_count = rte_compressdev_devices_get(test_data->driver_name,
			enabled_cdevs, RTE_COMPRESS_MAX_DEVS);
	if (enabled_cdev_count == 0) {
		RTE_LOG(ERR, USER1, "No compress devices type %s available,"
				    " please check the list of specified devices in EAL section\n",
				test_data->driver_name);
		return -EINVAL;
	}

	nb_lcores = rte_lcore_count() - 1;
	/*
	 * Use fewer devices,
	 * if there are more available than cores.
	 */
	if (enabled_cdev_count > nb_lcores) {
		if (nb_lcores == 0) {
			RTE_LOG(ERR, USER1, "Cannot run with 0 cores! Increase the number of cores\n");
			return -EINVAL;
		}
		enabled_cdev_count = nb_lcores;
		RTE_LOG(INFO, USER1,
			"There's more available devices than cores!"
			" The number of devices has been aligned to %d cores\n",
			nb_lcores);
	}

	/*
	 * Calculate number of needed queue pairs, based on the amount
	 * of available number of logical cores and compression devices.
	 * For instance, if there are 4 cores and 2 compression devices,
	 * 2 queue pairs will be set up per device.
	 * One queue pair per one core.
	 * if e.g.: there're 3 cores and 2 compression devices,
	 * 2 queue pairs will be set up per device but one queue pair
	 * will left unused in the last one device
	 */
	test_data->nb_qps = (nb_lcores % enabled_cdev_count) ?
				(nb_lcores / enabled_cdev_count) + 1 :
				nb_lcores / enabled_cdev_count;

	for (i = 0; i < enabled_cdev_count &&
			i < RTE_COMPRESS_MAX_DEVS; i++,
					nb_lcores -= test_data->nb_qps) {
		cdev_id = enabled_cdevs[i];

		struct rte_compressdev_info cdev_info;
		uint8_t socket_id = rte_compressdev_socket_id(cdev_id);

		rte_compressdev_info_get(cdev_id, &cdev_info);
		if (cdev_info.max_nb_queue_pairs &&
			test_data->nb_qps > cdev_info.max_nb_queue_pairs) {
			RTE_LOG(ERR, USER1,
				"Number of needed queue pairs is higher "
				"than the maximum number of queue pairs "
				"per device.\n");
			RTE_LOG(ERR, USER1,
				"Lower the number of cores or increase "
				"the number of crypto devices\n");
			return -EINVAL;
		}

		if (comp_perf_check_capabilities(test_data, cdev_id) < 0)
			return -EINVAL;

		/* Configure compressdev */
		struct rte_compressdev_config config = {
			.socket_id = socket_id,
			.nb_queue_pairs = nb_lcores > test_data->nb_qps
					? test_data->nb_qps : nb_lcores,
			.max_nb_priv_xforms = NUM_MAX_XFORMS,
			.max_nb_streams = 0
		};

		if (rte_compressdev_configure(cdev_id, &config) < 0) {
			RTE_LOG(ERR, USER1, "Device configuration failed\n");
			return -EINVAL;
		}

		for (j = 0; j < test_data->nb_qps; j++) {
			ret = rte_compressdev_queue_pair_setup(cdev_id, j,
					NUM_MAX_INFLIGHT_OPS, socket_id);
			if (ret < 0) {
				RTE_LOG(ERR, USER1,
			      "Failed to setup queue pair %u on compressdev %u",
					j, cdev_id);
				return -EINVAL;
			}
		}

		ret = rte_compressdev_start(cdev_id);
		if (ret < 0) {
			RTE_LOG(ERR, USER1,
				"Failed to start device %u: error %d\n",
				cdev_id, ret);
			return -EPERM;
		}
	}

	return enabled_cdev_count;
}

void
comp_perf_cleanup_on_signal(int signalNumber __rte_unused)
{
	test_data->perf_comp_force_stop = 1;
}

void
comp_perf_register_cleanup_on_signal(void)
{
	signal(SIGTERM, comp_perf_cleanup_on_signal);
	signal(SIGINT, comp_perf_cleanup_on_signal);
}

void
comp_perf_options_default(struct comp_test_data *test_data)
{
    test_data->seg_sz = 2048;
    test_data->burst_sz = 32;
    test_data->pool_sz = 8192;
    test_data->max_sgl_segs = 16;
    test_data->num_iter = 10000;
    test_data->huffman_enc = RTE_COMP_HUFFMAN_DYNAMIC;
    test_data->test_op = COMPRESS_DECOMPRESS;
    test_data->window_sz = -1;
    test_data->level_lst.min = RTE_COMP_LEVEL_MIN;
    test_data->level_lst.max = RTE_COMP_LEVEL_MAX;
    test_data->level_lst.inc = 1;
    test_data->test = CPERF_TEST_TYPE_THROUGHPUT;
    test_data->use_external_mbufs = 0;
    test_data->cyclecount_delay = 500;
}

#define required_argument  1

struct option lgopts[] = {
    { CPERF_DRIVER_NAME, required_argument, 0, 0 },
    { NULL, 0, 0, 0 }
};

int
parse_driver_name(struct comp_test_data *test_data, const char *arg)
{
    if (strlen(arg) > (sizeof(test_data->driver_name) - 1))
        return -1;

    strlcpy(test_data->driver_name, arg,
            sizeof(test_data->driver_name));

    return 0;
}

typedef int (*option_parser_t)(struct comp_test_data *test_data,
        const char *arg);

struct long_opt_parser {
    const char *lgopt_name;
    option_parser_t parser_fn;
};

int
comp_perf_opts_parse_long(int opt_idx, struct comp_test_data *test_data)
{
    struct long_opt_parser parsermap[] = {
        { CPERF_DRIVER_NAME,    parse_driver_name },
    };
    unsigned int i;

    for (i = 0; i < RTE_DIM(parsermap); i++) {
        if (strncmp(lgopts[opt_idx].name, parsermap[i].lgopt_name,
                strlen(lgopts[opt_idx].name)) == 0)
            return parsermap[i].parser_fn(test_data, optarg);
    }

    return -EINVAL;
}

int
comp_perf_options_parse(struct comp_test_data *test_data, int argc, char **argv)
{
    int opt, retval, opt_idx;

    while ((opt = getopt_long(argc, argv, "h", lgopts, &opt_idx)) != EOF) {
        switch (opt) {
        case 'h':
            usage(argv[0]);
            rte_exit(EXIT_SUCCESS, "Displayed help\n");
            break;
        /* long options */
        case 0:
            retval = comp_perf_opts_parse_long(opt_idx, test_data);
            if (retval != 0)
                return retval;

            break;

        default:
            usage(argv[0]);
            return -EINVAL;
        }
    }

    return 0;
}

int
comp_perf_options_check(struct comp_test_data *test_data)
{
    if (test_data->driver_name[0] == '\0') {
        RTE_LOG(ERR, USER1, "Driver name has to be set\n");
        return -1;
    }

    if (test_data->input_file[0] == '\0') {
        RTE_LOG(ERR, USER1, "Input file name has to be set\n");
        return -1;
    }

    return 0;
}

int
setup_eal(int argc, char **argv)
{
	uint8_t level_idx = 0;
	int ret, i;
	void *ctx[RTE_MAX_LCORE] = {};
	uint8_t enabled_cdevs[RTE_COMPRESS_MAX_DEVS];
	int nb_compressdevs = 0;
	uint16_t total_nb_qps = 0;
	uint8_t cdev_id;
	uint32_t lcore_id;

	/* Initialise DPDK EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments!\n");
	argc -= ret;
	argv += ret;

	test_data = rte_zmalloc_socket(NULL, sizeof(struct comp_test_data),
					0, rte_socket_id());

	if (test_data == NULL)
		rte_exit(EXIT_FAILURE, "Cannot reserve memory in socket %d\n",
				rte_socket_id());
    // register signal
	comp_perf_register_cleanup_on_signal();

	ret = EXIT_SUCCESS;
	test_data->cleanup = ST_TEST_DATA;
    // when use compress dev, use default options
	comp_perf_options_default(test_data);
    if (comp_perf_options_parse(test_data, argc, argv) < 0) {
        RTE_LOG(ERR, USER1,
            "Parsing one or more user options failed\n");
        ret = EXIT_FAILURE;
        return -1;
    }

    if (comp_perf_options_check(test_data) < 0) {
        ret = EXIT_FAILURE;
        return -1;
    }
	nb_compressdevs =
		comp_perf_initialize_compressdev(test_data, enabled_cdevs);

	if (nb_compressdevs < 1) {
		ret = EXIT_FAILURE;
		return -1;
	}

    total_nb_qps = nb_compressdevs * test_data->nb_qps;
    i = 0;
    uint8_t qp_id = 0, cdev_index = 0;

    RTE_LCORE_FOREACH_WORKER(lcore_id){
        if(i == total_nb_qps) break;
        cdev_id = enabled_cdevs[cdev_index];
        struct cperf_benchmark_ctx *ctx = compress_constructor(cdev_id, qp_id, test_data);
        if(ctx == NULL) {
            RTE_LOG(ERR, USER1, "Allocate ctx failed\n");
            return -1;
        }
        qp_id = (qp_id + 1) % test_data->nb_qps;
        if(qp_id == 0) cdev_index++;
        i++;
    }
    return ret;
}
