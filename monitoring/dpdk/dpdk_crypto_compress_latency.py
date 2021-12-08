#!/usr/bin/python
#
# This is a Hello World example that uses BPF_PERF_OUTPUT.

from bcc import BPF
from bcc.utils import printb
from dataclasses import dataclass
# define BPF program
prog = """
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#include "include/mbuf.h"
#include "include/packet.h"
#define KEY 1234
#define RTE_KEY 4567
#define RTE_KEY_FIRST 7890
#define RTE_DEV_KEY 5678

struct data_t {
    u64 count;
    u32 pid;
    u64 ts;
    u64 bytes;
};

BPF_PERF_OUTPUT(mlx5_tx_burst_none_empw_enter_events);
BPF_PERF_OUTPUT(mlx5_tx_burst_i_empw_enter_events);
BPF_PERF_OUTPUT(mlx5_tx_handle_completion_enter_events);
BPF_PERF_OUTPUT(rte_lcore_count_enter_events);
BPF_PERF_OUTPUT(rte_cryptodev_enqueue_burst_enter_events);
BPF_PERF_OUTPUT(rte_cryptodev_dequeue_burst_enter_events);
BPF_PERF_OUTPUT(rte_compressdev_enqueue_burst_enter_events);
BPF_PERF_OUTPUT(rte_compressdev_dequeue_burst_enter_events);
BPF_PERF_OUTPUT(openssl_pmd_enqueue_burst_enter_events);
BPF_PERF_OUTPUT(openssl_pmd_dequeue_burst_enter_events);

BPF_PERF_OUTPUT(mlx5_tx_burst_none_empw_exit_events);
BPF_PERF_OUTPUT(mlx5_tx_burst_i_empw_exit_events);
BPF_PERF_OUTPUT(mlx5_tx_handle_completion_exit_events);
BPF_PERF_OUTPUT(rte_lcore_count_exit_events);
BPF_PERF_OUTPUT(rte_pktmbuf_pool_create_exit_events);
BPF_PERF_OUTPUT(rte_cryptodev_enqueue_burst_exit_events);
BPF_PERF_OUTPUT(rte_cryptodev_dequeue_burst_exit_events);
BPF_PERF_OUTPUT(openssl_pmd_enqueue_burst_exit_events);
BPF_PERF_OUTPUT(openssl_pmd_dequeue_burst_exit_events);
BPF_PERF_OUTPUT(rte_compressdev_enqueue_burst_exit_events);
BPF_PERF_OUTPUT(rte_compressdev_dequeue_burst_exit_events);

BPF_PERF_OUTPUT(rte_eth_dev_count_avail_exit_events);

BPF_HASH(current_count, u64);
BPF_HASH(rte_lcore_count, u64);
BPF_HASH(rte_first, u64);
BPF_HASH(rte_dev_count, u64);

int rte_pktmbuf_pool_create_exit_latency(struct pt_regs *ctx){
    struct data_t data = {};
    u64 start_key = RTE_KEY_FIRST, zero = 0;
    u64 *cri = rte_first.lookup_or_try_init(&start_key, &zero);
    if(cri == NULL) return 0;

    *cri += 1;
    rte_first.update(&start_key, cri);
    rte_pktmbuf_pool_create_exit_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int rte_eth_dev_count_avail_exit_latency(struct pt_regs *ctx){
    struct data_t data = {};
    u64 count_key = KEY, rte_dev_key = RTE_DEV_KEY, rte_first_key = RTE_KEY_FIRST,  zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&count_key, &zero);
    if(cur_cnt == NULL) return 0;
    u64 *dev_cnt = rte_dev_count.lookup_or_try_init(&rte_dev_key, &zero);
    if(dev_cnt == NULL) return 0;
    u64 *cri = rte_first.lookup_or_try_init(&rte_first_key, &zero);
    if(cri == NULL) return 0;

    if(*cri == 0) return 0;
    if(*dev_cnt + 1 >= 2){
        data.pid = bpf_get_current_pid_tgid();
        data.count = *cur_cnt;
        data.ts = bpf_ktime_get_ns();

        *dev_cnt = 0;
        *cur_cnt += 1;
        current_count.update(&count_key, cur_cnt);
        rte_dev_count.update(&rte_dev_key, dev_cnt);
        rte_eth_dev_count_avail_exit_events.perf_submit(ctx, &data, sizeof(data));
    }
    else{
        *dev_cnt += 1;
        rte_dev_count.update(&rte_dev_key, dev_cnt);
    }
    return 0;
}

int rte_lcore_count_enter_latency(struct pt_regs *ctx){
    struct data_t data = {};
    u64 key = KEY, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    rte_lcore_count_enter_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int rte_lcore_count_exit_latency(struct pt_regs *ctx){
    struct data_t data = {};
    u64 key = KEY, rte_key = RTE_KEY, rte_key_first = RTE_KEY_FIRST, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;
    u64 *rte_cnt = rte_lcore_count.lookup_or_try_init(&rte_key, &zero);
    if(rte_cnt == NULL) return 0;
    u64 *cri = rte_first.lookup_or_try_init(&rte_key_first, &zero);
    if(cri == NULL) return 0;

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    if(*cri == 0) return 0;
    if(*rte_cnt + 1 >= 2) {
        *rte_cnt = 0;
        rte_lcore_count.update(&rte_key, rte_cnt);
        rte_lcore_count_exit_events.perf_submit(ctx, &data, sizeof(data));
    }
    else {
        *rte_cnt += 1;
        rte_lcore_count.update(&rte_key, rte_cnt);
    }
    return 0;
}

int mlx5_tx_burst_none_empw_enter_latency(struct pt_regs *ctx){
    struct data_t data = {};
    u64 key = KEY, *curr, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;
    u32 pkt_cnt = PT_REGS_RC(ctx);
    struct rte_mbuf **pkts = (struct rte_mbuf **)PT_REGS_PARM2(ctx);

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    for(int i = 0 ; i < 32 ; i++){
        if(i >= pkt_cnt) break;
        struct rte_mbuf *mbuf = pkts[i];
        if(mbuf == 0x0) break;
        data.bytes += mbuf->pkt_len;
    }

    mlx5_tx_burst_none_empw_enter_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int mlx5_tx_burst_none_empw_exit_latency(struct pt_regs *ctx){
    struct data_t data = {};
    u64 key = KEY, *curr, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
 
    mlx5_tx_burst_none_empw_exit_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int mlx5_tx_burst_i_empw_enter_latency(struct pt_regs *ctx){
    struct data_t data = {};
    u64 key = KEY, *curr, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;
    u32 pkt_cnt = PT_REGS_RC(ctx);
    struct rte_mbuf **pkts = (struct rte_mbuf **)PT_REGS_PARM2(ctx);

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
   
    for(int i = 0 ; i < 32 ; i++){
        if(i >= pkt_cnt) break;
        struct rte_mbuf *mbuf = pkts[i];
        if(mbuf == 0x0) break;
        data.bytes += mbuf->pkt_len;
    }

    mlx5_tx_burst_i_empw_enter_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int mlx5_tx_burst_i_empw_exit_latency(struct pt_regs *ctx){
    struct data_t data = {};
    u64 key = KEY, *curr, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
   
    mlx5_tx_burst_i_empw_exit_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int mlx5_tx_handle_completion_enter_latency(struct pt_regs *ctx){
    struct data_t data = {};
    u64 key = KEY, *curr, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    mlx5_tx_handle_completion_enter_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int mlx5_tx_handle_completion_exit_latency(struct pt_regs *ctx){
    struct data_t data = {};
    u64 key = KEY, *curr, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    mlx5_tx_handle_completion_exit_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int rte_cryptodev_enqueue_burst_enter_latency(struct pt_regs *ctx){
    struct data_t data = {};
    u64 key = KEY, *curr, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    rte_cryptodev_enqueue_burst_enter_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int rte_cryptodev_enqueue_burst_exit_latency(struct pt_regs *ctx){
    struct data_t data = {};
    u64 key = KEY, *curr, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    rte_cryptodev_enqueue_burst_exit_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int rte_compressdev_enqueue_burst_enter_latency(struct pt_regs *ctx){
    struct data_t data = {};
    u64 key = KEY, *curr, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    rte_compressdev_enqueue_burst_enter_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int rte_compressdev_enqueue_burst_exit_latency(struct pt_regs *ctx){
    struct data_t data = {};
    u64 key = KEY, *curr, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    rte_compressdev_enqueue_burst_exit_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int rte_cryptodev_dequeue_burst_enter_latency(struct pt_regs *ctx){
    struct data_t data = {};
    u64 key = KEY, *curr, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    rte_cryptodev_dequeue_burst_enter_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int rte_cryptodev_dequeue_burst_exit_latency(struct pt_regs *ctx){
    struct data_t data = {};
    u64 key = KEY, *curr, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    rte_cryptodev_dequeue_burst_exit_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int rte_compressdev_dequeue_burst_enter_latency(struct pt_regs *ctx){
    struct data_t data = {};
    u64 key = KEY, *curr, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    rte_compressdev_dequeue_burst_enter_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int rte_compressdev_dequeue_burst_exit_latency(struct pt_regs *ctx){
    struct data_t data = {};
    u64 key = KEY, *curr, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    rte_compressdev_dequeue_burst_exit_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int openssl_pmd_enqueue_burst_enter_latency(struct pt_regs *ctx){
    struct data_t data = {};
    u64 key = KEY, *curr, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    openssl_pmd_enqueue_burst_enter_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int openssl_pmd_enqueue_burst_exit_latency(struct pt_regs *ctx){
    struct data_t data = {};
    u64 key = KEY, *curr, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    openssl_pmd_enqueue_burst_exit_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int openssl_pmd_dequeue_burst_enter_latency(struct pt_regs *ctx){
    struct data_t data = {};
    u64 key = KEY, *curr, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    openssl_pmd_dequeue_burst_enter_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int openssl_pmd_dequeue_burst_exit_latency(struct pt_regs* ctx){
    struct data_t data = {};
    u64 key = KEY, *curr, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    openssl_pmd_dequeue_burst_exit_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

divide_num_sec = 1000000000
dpdk_function_list = ["rte_lcore_count", "mlx5_tx_burst_none_empw", "mlx5_tx_burst_i_empw", "mlx5_tx_handle_completion", "openssl_pmd_enqueue_burst", "openssl_pmd_dequeue_burst", "rte_compressdev_enqueue_burst", "rte_compressdev_dequeue_burst"]
# DPDK의 공유라이브러리의 위치이다.
shared_library_path="/usr/local/lib/x86_64-linux-gnu/"

library_name = {}
library_name["rte_lcore_count"] = "librte_cryptodev.so"
library_name["mlx5_tx_burst_none_empw"] = "librte_net_mlx5.so"
library_name["mlx5_tx_burst_i_empw"] = "librte_net_mlx5.so"
library_name["mlx5_tx_handle_completion"] = "librte_net_mlx5.so"
library_name["openssl_pmd_enqueue_burst"] = "librte_crypto_openssl.so"
library_name["openssl_pmd_dequeue_burst"] = "librte_crypto_openssl.so"
library_name["rte_compressdev_enqueue_burst"] = "librte_compressdev.so"
library_name["rte_compressdev_dequeue_burst"] = "librte_compressdev.so"

data_list = {}
log_list = []
last_called = {}

fp = open('tx_log.txt', 'w')

b = BPF(text = prog)
b.attach_uretprobe(name = shared_library_path + "librte_mbuf.so", sym = "rte_pktmbuf_pool_create", fn_name = "rte_pktmbuf_pool_create_exit_latency")
b.attach_uretprobe(name = shared_library_path + "librte_ethdev.so", sym = "rte_eth_dev_count_avail", fn_name = "rte_eth_dev_count_avail_exit_latency")

for func_name in dpdk_function_list:
    if func_name == "rte_lcore_count":
        b.attach_uprobe(name = shared_library_path + library_name[func_name], sym = "rte_cryptodev_count", fn_name = func_name + "_enter_latency")
        b.attach_uretprobe(name = shared_library_path + library_name[func_name], sym = "rte_cryptodev_count", fn_name = func_name + "_exit_latency")
    else:
        b.attach_uprobe(name = shared_library_path + library_name[func_name], sym = func_name, fn_name = func_name + "_enter_latency")
        b.attach_uretprobe(name = shared_library_path + library_name[func_name], sym = func_name, fn_name = func_name + "_exit_latency")

def rte_pktmbuf_pool_create_exit_event(cpu, data, size):
    print('called')

def rte_eth_dev_count_avail_exit_event(cpu, data, size):
    event = b["rte_eth_dev_count_avail_exit_events"].event(data)
    '''
    for func_name in dpdk_function_list:
        fn_name = func_name + "_enter"
        if data_list.get(fn_name) == None or last_called.get(fn_name) == None : continue
        if data_list[fn_name].get(event.pid) == None or last_called[fn_name].get(event.pid) == None : continue
        if data_list[fn_name][event.pid].get(event.count) and last_called[fn_name][event.pid].get(event.count):
            ts = last_called[fn_name][event.pid][event.count] - data_list[fn_name][event.pid][event.count]
            if func_name == "rte_lcore_count":
                log_list.append([event.count, "make_packets", ts])
            else:
                log_list.append([event.count, func_name, ts])
    '''

def mlx5_tx_burst_none_empw_enter_event(cpu, data, size):
    func_name = "mlx5_tx_burst_none_empw_enter"
    event = b[func_name + "_events"].event(data)

    exist = data_list.get(func_name)
    if exist == None:
        data_list[func_name] = {}
    exist = data_list[func_name].get(event.pid)
    if exist == None:
        data_list[func_name][event.pid] = {}
    exist = data_list[func_name][event.pid].get(event.count)
    if exist == None:
        data_list[func_name][event.pid][event.count] = 0

    exist = data_list[func_name][event.pid].get(event.count)
    if exist : return
    data_list[func_name][event.pid][event.count] = event.ts

def mlx5_tx_burst_none_empw_exit_event(cpu, data, size):
    enter_func_name = "mlx5_tx_burst_none_empw_enter"
    exit_func_name = "mlx5_tx_burst_none_empw_exit"
    func_name = "mlx5_tx_burst_none_empw"
    event = b[exit_func_name + "_events"].event(data)

    if data_list[enter_func_name][event.pid].get(event.count) == None:
        return
    exist = last_called.get(enter_func_name)
    if exist == None:
        last_called[enter_func_name] = {}
    exist = last_called[enter_func_name].get(event.pid)
    if exist == None:
        last_called[enter_func_name][event.pid] = {}

    last_called[enter_func_name][event.pid][event.count] = event.ts
    if data_list.get(enter_func_name) == None : return
    if data_list[enter_func_name].get(event.pid) == None : return
    if data_list[enter_func_name][event.pid].get(event.count) == None : return
    fp_w = open('tx_log.txt', 'a')
    fp_w.write(str(event.count) + ' ' + func_name + ' ' + str((event.ts - data_list[enter_func_name][event.pid][event.count]) / divide_num_sec) + '\n')
    fp_w.close()

def mlx5_tx_burst_i_empw_enter_event(cpu, data, size):
    func_name = "mlx5_tx_burst_i_empw_enter"
    event = b[func_name + "_events"].event(data)

    exist = data_list.get(func_name)
    if exist == None:
        data_list[func_name] = {}
    exist = data_list[func_name].get(event.pid)
    if exist == None:
        data_list[func_name][event.pid] = {}
    exist = data_list[func_name][event.pid].get(event.count)
    if exist == None:
        data_list[func_name][event.pid][event.count] = 0

    exist = data_list[func_name][event.pid].get(event.count)
    if exist : return
    data_list[func_name][event.pid][event.count] = event.ts

def mlx5_tx_burst_i_empw_exit_event(cpu, data, size):
    enter_func_name = "mlx5_tx_burst_i_empw_enter"
    exit_func_name = "mlx5_tx_burst_i_empw_exit"
    func_name = "mlx5_tx_burst_i_empw"
    event = b[exit_func_name + "_events"].event(data)

    if data_list[enter_func_name][event.pid].get(event.count) == None:
        return
    exist = last_called.get(enter_func_name)
    if exist == None:
        last_called[enter_func_name] = {}
    exist = last_called[enter_func_name].get(event.pid)
    if exist == None:
        last_called[enter_func_name][event.pid] = {}

    last_called[enter_func_name][event.pid][event.count] = event.ts
    if data_list.get(enter_func_name) == None : return
    if data_list[enter_func_name].get(event.pid) == None : return
    if data_list[enter_func_name][event.pid].get(event.count) == None : return
    fp_w = open('tx_log.txt', 'a')
    fp_w.write(str(event.count) + ' ' + func_name + ' ' + str((event.ts - data_list[enter_func_name][event.pid][event.count]) / divide_num_sec) + '\n')
    fp_w.close()

def mlx5_tx_handle_completion_enter_event(cpu, data, size):
    func_name = "mlx5_tx_handle_completion_enter"
    event = b[func_name + "_events"].event(data)

    exist = data_list.get(func_name)
    if exist == None:
        data_list[func_name] = {}
    exist = data_list[func_name].get(event.pid)
    if exist == None:
        data_list[func_name][event.pid] = {}
    exist = data_list[func_name][event.pid].get(event.count)
    if exist == None:
        data_list[func_name][event.pid][event.count] = 0
    
    exist = data_list[func_name][event.pid].get(event.count)
    if exist : return
    data_list[func_name][event.pid][event.count] = event.ts

def mlx5_tx_handle_completion_exit_event(cpu, data, size):
    enter_func_name = "mlx5_tx_handle_completion_enter"
    exit_func_name = "mlx5_tx_handle_completion_exit"
    func_name = "mlx5_tx_handle_completion_empw"
    event = b[exit_func_name + "_events"].event(data)

    if data_list[enter_func_name][event.pid].get(event.count) == None:
        return
    exist = last_called.get(enter_func_name)
    if exist == None:
        last_called[enter_func_name] = {}
    exist = last_called[enter_func_name].get(event.pid)
    if exist == None:
        last_called[enter_func_name][event.pid] = {}

    last_called[enter_func_name][event.pid][event.count] = event.ts
    if data_list.get(enter_func_name) == None : return
    if data_list[enter_func_name].get(event.pid) == None : return
    if data_list[enter_func_name][event.pid].get(event.count) == None : return
    fp_w = open('tx_log.txt', 'a')
    fp_w.write(str(event.count) + ' ' + func_name + ' ' + str((event.ts - data_list[enter_func_name][event.pid][event.count]) / divide_num_sec) + '\n')
    fp_w.close()


def rte_lcore_count_enter_event(cpu, data, size):
    func_name = "rte_lcore_count_enter"
    event = b[func_name + "_events"].event(data)

    exist = data_list.get(func_name)
    if exist == None:
        data_list[func_name] = {}
    exist = data_list[func_name].get(event.pid)
    if exist == None:
        data_list[func_name][event.pid] = {}
    exist = data_list[func_name][event.pid].get(event.count)
    if exist == None:
        data_list[func_name][event.pid][event.count] = 0

    exist = data_list[func_name][event.pid].get(event.count)
    if exist : return
    data_list[func_name][event.pid][event.count] = event.ts

def rte_lcore_count_exit_event(cpu, data, size):
    enter_func_name = "rte_lcore_count_enter"
    exit_func_name = "rte_lcore_count_exit"
    func_name = "rte_lcore_count"
    event = b[exit_func_name + "_events"].event(data)

    if data_list[enter_func_name][event.pid].get(event.count) == None:
        return
    exist = last_called.get(enter_func_name)
    if exist == None:
        last_called[enter_func_name] = {}
    exist = last_called[enter_func_name].get(event.pid)
    if exist == None:
        last_called[enter_func_name][event.pid] = {}

    last_called[enter_func_name][event.pid][event.count] = event.ts
    if data_list.get(enter_func_name) == None : return
    if data_list[enter_func_name].get(event.pid) == None : return
    if data_list[enter_func_name][event.pid].get(event.count) == None : return
    fp_w = open('tx_log.txt', 'a')
    fp_w.write(str(event.count) + ' ' + "make_packet" + ' ' + str((event.ts - data_list[enter_func_name][event.pid][event.count]) / divide_num_sec) + '\n')
    fp_w.close()


def openssl_pmd_enqueue_burst_enter_event(cpu, data, size): 
    func_name = "openssl_pmd_enqueue_burst_enter"
    event = b[func_name + "_events"].event(data)

    exist = data_list.get(func_name)
    if exist == None:
        data_list[func_name] = {}
    exist = data_list[func_name].get(event.pid)
    if exist == None:
        data_list[func_name][event.pid] = {}
    exist = data_list[func_name][event.pid].get(event.count)
    if exist == None:
        data_list[func_name][event.pid][event.count] = 0

    exist = data_list[func_name][event.pid].get(event.count)
    if exist : return
    data_list[func_name][event.pid][event.count] = event.ts

def openssl_pmd_enqueue_burst_exit_event(cpu, data, size):
    enter_func_name = "openssl_pmd_enqueue_burst_enter"
    exit_func_name = "openssl_pmd_enqueue_burst_exit"
    func_name = "openssl_pmd_enqueue_burst"
    event = b[exit_func_name + "_events"].event(data)

    if data_list[enter_func_name][event.pid].get(event.count) == None:
        return
    exist = last_called.get(enter_func_name)
    if exist == None:
        last_called[enter_func_name] = {}
    exist = last_called[enter_func_name].get(event.pid)
    if exist == None:
        last_called[enter_func_name][event.pid] = {}

    last_called[enter_func_name][event.pid][event.count] = event.ts
    if data_list.get(enter_func_name) == None : return
    if data_list[enter_func_name].get(event.pid) == None : return
    if data_list[enter_func_name][event.pid].get(event.count) == None : return
    fp_w = open('tx_log.txt', 'a')
    fp_w.write(str(event.count) + ' ' + func_name + ' ' + str((event.ts - data_list[enter_func_name][event.pid][event.count]) / divide_num_sec) + '\n')
    fp_w.close()

def openssl_pmd_dequeue_burst_enter_event(cpu, data, size):
    func_name = "openssl_pmd_dequeue_burst_enter"
    event = b[func_name + "_events"].event(data)

    exist = data_list.get(func_name)
    if exist == None:
        data_list[func_name] = {}
    exist = data_list[func_name].get(event.pid)
    if exist == None:
        data_list[func_name][event.pid] = {}
    exist = data_list[func_name][event.pid].get(event.count)
    if exist == None:
        data_list[func_name][event.pid][event.count] = 0

    exist = data_list[func_name][event.pid].get(event.count)
    if exist : return
    data_list[func_name][event.pid][event.count] = event.ts

def openssl_pmd_dequeue_burst_exit_event(cpu, data, size):
    enter_func_name = "openssl_pmd_dequeue_burst_enter"
    exit_func_name = "openssl_pmd_dequeue_burst_exit"
    func_name = "openssl_pmd_dequeue_burst"
    event = b[exit_func_name + "_events"].event(data)

    if data_list[enter_func_name][event.pid].get(event.count) == None:
        return
    exist = last_called.get(enter_func_name)
    if exist == None:
        last_called[enter_func_name] = {}
    exist = last_called[enter_func_name].get(event.pid)
    if exist == None:
        last_called[enter_func_name][event.pid] = {}

    last_called[enter_func_name][event.pid][event.count] = event.ts
    if data_list.get(enter_func_name) == None : return
    if data_list[enter_func_name].get(event.pid) == None : return
    if data_list[enter_func_name][event.pid].get(event.count) == None : return
    fp_w = open('tx_log.txt', 'a')
    fp_w.write(str(event.count) + ' ' + func_name + ' ' + str((event.ts - data_list[enter_func_name][event.pid][event.count]) / divide_num_sec) + '\n')
    fp_w.close()

def rte_compressdev_enqueue_burst_enter_event(cpu, data, size):
    func_name = "rte_compressdev_enqueue_burst_enter"
    event = b[func_name + "_events"].event(data)

    exist = data_list.get(func_name)
    if exist == None:
        data_list[func_name] = {}
    exist = data_list[func_name].get(event.pid)
    if exist == None:
        data_list[func_name][event.pid] = {}
    exist = data_list[func_name][event.pid].get(event.count)
    if exist == None:
        data_list[func_name][event.pid][event.count] = 0

    exist = data_list[func_name][event.pid].get(event.count)
    if exist : return
    data_list[func_name][event.pid][event.count] = event.ts

def rte_compressdev_enqueue_burst_exit_event(cpu, data, size):
    enter_func_name = "rte_compressdev_enqueue_burst_enter"
    exit_func_name = "rte_compressdev_enqueue_burst_exit"
    func_name = "rte_compressdev_enqueue_burst"
    event = b[exit_func_name + "_events"].event(data)

    if data_list[enter_func_name][event.pid].get(event.count) == None:
        return
    exist = last_called.get(enter_func_name)
    if exist == None:
        last_called[enter_func_name] = {}
    exist = last_called[enter_func_name].get(event.pid)
    if exist == None:
        last_called[enter_func_name][event.pid] = {}

    last_called[enter_func_name][event.pid][event.count] = event.ts
    if data_list.get(enter_func_name) == None : return
    if data_list[enter_func_name].get(event.pid) == None : return
    if data_list[enter_func_name][event.pid].get(event.count) == None : return
    fp_w = open('tx_log.txt', 'a')
    fp_w.write(str(event.count) + ' ' + func_name + ' ' + str((event.ts - data_list[enter_func_name][event.pid][event.count]) / divide_num_sec) + '\n')
    fp_w.close()

def rte_compressdev_dequeue_burst_enter_event(cpu, data, size):
    func_name = "rte_compressdev_enqueue_burst_enter"
    event = b[func_name + "_events"].event(data)

    exist = data_list.get(func_name)
    if exist == None:
        data_list[func_name] = {}
    exist = data_list[func_name].get(event.pid)
    if exist == None:
        data_list[func_name][event.pid] = {}
    exist = data_list[func_name][event.pid].get(event.count)
    if exist == None:
        data_list[func_name][event.pid][event.count] = 0

    exist = data_list[func_name][event.pid].get(event.count)
    if exist : return
    data_list[func_name][event.pid][event.count] = event.ts

def rte_compressdev_dequeue_burst_exit_event(cpu, data, size):
    enter_func_name = "rte_compressdev_dequeue_burst_enter"
    exit_func_name = "rte_compressdev_dequeue_burst_exit"
    func_name = "rte_compressdev_dequeue_burst"
    event = b[exit_func_name + "_events"].event(data)

    if data_list[enter_func_name][event.pid].get(event.count) == None:
        return
    exist = last_called.get(enter_func_name)
    if exist == None:
        last_called[enter_func_name] = {}
    exist = last_called[enter_func_name].get(event.pid)
    if exist == None:
        last_called[enter_func_name][event.pid] = {}

    last_called[enter_func_name][event.pid][event.count] = event.ts
    if data_list.get(enter_func_name) == None : return
    if data_list[enter_func_name].get(event.pid) == None : return
    if data_list[enter_func_name][event.pid].get(event.count) == None : return
    fp_w = open('tx_log.txt', 'a')
    fp_w.write(str(event.count) + ' ' + func_name + ' ' + str((event.ts - data_list[enter_func_name][event.pid][event.count]) / divide_num_sec) + '\n')
    fp_w.close()

# loop with callback to print_event
b["mlx5_tx_burst_none_empw_enter_events"].open_perf_buffer(mlx5_tx_burst_none_empw_enter_event)
b["mlx5_tx_handle_completion_enter_events"].open_perf_buffer(mlx5_tx_handle_completion_enter_event)
b["mlx5_tx_burst_i_empw_enter_events"].open_perf_buffer(mlx5_tx_burst_i_empw_enter_event)
b["rte_lcore_count_enter_events"].open_perf_buffer(rte_lcore_count_enter_event)
b["openssl_pmd_enqueue_burst_enter_events"].open_perf_buffer(openssl_pmd_enqueue_burst_enter_event)
b["openssl_pmd_dequeue_burst_enter_events"].open_perf_buffer(openssl_pmd_dequeue_burst_enter_event)
b["rte_compressdev_enqueue_burst_enter_events"].open_perf_buffer(rte_compressdev_enqueue_burst_enter_event)
b["rte_compressdev_dequeue_burst_enter_events"].open_perf_buffer(rte_compressdev_dequeue_burst_enter_event)

b["mlx5_tx_burst_none_empw_exit_events"].open_perf_buffer(mlx5_tx_burst_none_empw_exit_event)
b["mlx5_tx_handle_completion_exit_events"].open_perf_buffer(mlx5_tx_handle_completion_exit_event)
b["mlx5_tx_burst_i_empw_exit_events"].open_perf_buffer(mlx5_tx_burst_i_empw_exit_event)
b["rte_lcore_count_exit_events"].open_perf_buffer(rte_lcore_count_exit_event)
b["rte_pktmbuf_pool_create_exit_events"].open_perf_buffer(rte_pktmbuf_pool_create_exit_event)
b["rte_eth_dev_count_avail_exit_events"].open_perf_buffer(rte_eth_dev_count_avail_exit_event)
b["openssl_pmd_enqueue_burst_exit_events"].open_perf_buffer(openssl_pmd_enqueue_burst_exit_event)
b["openssl_pmd_dequeue_burst_exit_events"].open_perf_buffer(openssl_pmd_dequeue_burst_exit_event)
b["rte_compressdev_enqueue_burst_enter_events"].open_perf_buffer(rte_compressdev_enqueue_burst_exit_event)
b["rte_compressdev_dequeue_burst_enter_events"].open_perf_buffer(rte_compressdev_dequeue_burst_exit_event)

def print_latency():
    print('start save log')
    for data in log_list:
        fp.write(str(data[0]) + ' ' + str(data[1]) + ' ' + str(float(data[2] / divide_num_sec)) + '\n')
    print('end save log')

print('Start')
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        #print_latency()
        exit()
