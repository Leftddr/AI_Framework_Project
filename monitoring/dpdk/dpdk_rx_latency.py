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
#define RTE_DEV_KEY 4567
#define RTE_KEY_FIRST 7890

struct data_t {
    u64 count;
    u32 pid;
    u64 ts;
    u64 bytes;
};

BPF_PERF_OUTPUT(mlx5_rx_burst_enter_events);
BPF_PERF_OUTPUT(mlx5_rx_burst_vec_enter_events);
BPF_PERF_OUTPUT(rxq_cq_decompress_v_enter_events);
BPF_PERF_OUTPUT(rxq_cq_process_v_enter_events);
BPF_PERF_OUTPUT(mlx5_rx_burst_mprq_vec_enter_events);

BPF_PERF_OUTPUT(mlx5_rx_burst_exit_events);
BPF_PERF_OUTPUT(mlx5_rx_burst_vec_exit_events);
BPF_PERF_OUTPUT(rxq_cq_decompress_v_exit_events);
BPF_PERF_OUTPUT(rxq_cq_process_v_exit_events);
BPF_PERF_OUTPUT(mlx5_rx_burst_mprq_vec_exit_events);
BPF_PERF_OUTPUT(rte_eth_dev_count_avail_exit_events);
BPF_PERF_OUTPUT(rte_pktmbuf_pool_create_exit_events);

BPF_HASH(current_count, u64);
BPF_HASH(rte_dev, u64);
BPF_HASH(rte_first, u64);

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
    u64 key = KEY, rte_dev_key = RTE_DEV_KEY, rte_first_key = RTE_KEY_FIRST, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;
    u64 *dev_cnt = rte_dev.lookup_or_try_init(&rte_dev_key, &zero);
    if(dev_cnt == NULL) return 0;
    u64 *cri = rte_first.lookup(&rte_first_key);
    if(cri == NULL) return 0;

    if(*cri == 0) return 0;
    if(*dev_cnt + 1 >= 2){
        data.pid = bpf_get_current_pid_tgid();
        data.count = *cur_cnt;
        data.ts = bpf_ktime_get_ns();

        *dev_cnt = 0;
        *cur_cnt += 1;
        
        current_count.update(&key, cur_cnt);
        rte_dev.update(&rte_dev_key, dev_cnt);
        rte_eth_dev_count_avail_exit_events.perf_submit(ctx, &data, sizeof(data));
    }
    else {
        *dev_cnt += 1;
        rte_dev.update(&rte_dev_key, dev_cnt);
    }
    return 0;
}

int mlx5_rx_burst_enter_latency(struct pt_regs *ctx) {
    struct data_t data = {};
    u64 key = KEY, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    mlx5_rx_burst_enter_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int mlx5_rx_burst_exit_latency(struct pt_regs *ctx) {
    struct data_t data = {};
    u64 key = KEY, zero = 0;
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

    mlx5_rx_burst_exit_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int mlx5_rx_burst_vec_enter_latency(struct pt_regs *ctx) {
    struct data_t data = {};
    u64 key = KEY, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    mlx5_rx_burst_vec_enter_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int mlx5_rx_burst_vec_exit_latency(struct pt_regs *ctx) {
    struct data_t data = {};
    u64 key = KEY, zero = 0;
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
    mlx5_rx_burst_vec_exit_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int rxq_cq_decompress_v_enter_latency(struct pt_regs *ctx) {
    struct data_t data = {};
    u64 key = KEY, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    rxq_cq_decompress_v_enter_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int rxq_cq_decompress_v_exit_latency(struct pt_regs *ctx) {
    struct data_t data = {};
    u64 key = KEY, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    rxq_cq_decompress_v_exit_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int rxq_cq_process_v_enter_latency(struct pt_regs *ctx) {
    struct data_t data = {};
    u64 key = KEY, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    rxq_cq_process_v_enter_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int rxq_cq_process_v_exit_latency(struct pt_regs *ctx) {
    struct data_t data = {};
    u64 key = KEY, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    rxq_cq_process_v_exit_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int mlx5_rx_burst_mprq_vec_enter_latency(struct pt_regs *ctx){
    struct data_t data = {};
    u64 key = KEY, zero = 0;
    u64 *cur_cnt = current_count.lookup_or_try_init(&key, &zero);
    if(cur_cnt == NULL) return 0;

    data.count = *cur_cnt;
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    mlx5_rx_burst_mprq_vec_enter_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
} 

int mlx5_rx_burst_mprq_vec_exit_latency(struct pt_regs *ctx){
    struct data_t data = {};
    u64 key = KEY, zero = 0;
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
    
    mlx5_rx_burst_mprq_vec_exit_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""
divide_num_sec = 1000000000
# DPDK의 공유라이브러리의 위치이다.
# shared_library_path="/opt/mellanox/dpdk/lib/x86_64-linux-gnu/"
shared_library_path="/usr/local/lib/x86_64-linux-gnu/"
dpdk_function_list = ["mlx5_rx_burst", "mlx5_rx_burst_vec", "rxq_cq_decompress_v", "rxq_cq_process_v", "mlx5_rx_burst_mprq_vec"]

library_name = {}
library_name["mlx5_rx_burst"] = "librte_net_mlx5.so"
library_name["mlx5_rx_burst_vec"] = "librte_net_mlx5.so"
library_name["rxq_cq_decompress_v"] = "librte_net_mlx5.so"
library_name["rxq_cq_process_v"] = "librte_net_mlx5.so"
library_name["mlx5_rx_burst_mprq_vec"] = "librte_net_mlx5.so"
# load BPF program
# DPDK를 운용할 때 기본 설정을 위한 함수들이다.
b = BPF(text=prog)
b.attach_uretprobe(name = shared_library_path + "librte_mbuf.so", sym = "rte_pktmbuf_pool_create", fn_name = "rte_pktmbuf_pool_create_exit_latency")
b.attach_uretprobe(name = shared_library_path + "librte_ethdev.so", sym = "rte_eth_dev_count_avail", fn_name = "rte_eth_dev_count_avail_exit_latency")
for func_name in dpdk_function_list:
    b.attach_uprobe(name = shared_library_path + library_name[func_name], sym = func_name, fn_name = func_name + "_enter_latency")
    b.attach_uretprobe(name = shared_library_path + library_name[func_name], sym = func_name, fn_name = func_name + "_exit_latency")

data_list = {}
log_list = []
last_called = {}

fp = open('rx_log.txt', 'w')

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

def mlx5_rx_burst_enter_event(cpu, data, size):
    func_name = "mlx5_rx_burst_enter"
    event = b[func_name + "_events"].event(data)

    exist = data_list.get(func_name)
    if exist == None:
        data_list[func_name] = {}
    exist = data_list[func_name].get(event.pid)
    if exist == None:
        data_list[func_name][event.pid] = {}

    if data_list[func_name][event.pid].get(event.count) : return
    data_list[func_name][event.pid][event.count] = event.ts

def mlx5_rx_burst_exit_event(cpu, data, size):
    enter_func_name = "mlx5_rx_burst_enter"
    exit_func_name = "mlx5_rx_burst_exit"
    func_name = "mlx5_rx_burst"
    event = b[exit_func_name + "_events"].event(data)

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
    fp_w = open('rx_log.txt', 'a')
    fp_w.write(str(event.count) + ' ' + func_name + ' ' + str((event.ts - data_list[enter_func_name][event.pid][event.count]) / divide_num_sec) + '\n')
    fp_w.close() 

def mlx5_rx_burst_vec_enter_event(cpu, data, size):
    func_name = "mlx5_rx_burst_vec_enter"
    event = b[func_name + "_events"].event(data)

    exist = data_list.get(func_name)
    if exist == None:
        data_list[func_name] = {}
    exist = data_list[func_name].get(event.pid)
    if exist == None:
        data_list[func_name][event.pid] = {}

    if data_list[func_name][event.pid].get(event.count) : return
    data_list[func_name][event.pid][event.count] = event.ts

def mlx5_rx_burst_vec_exit_event(cpu, data, size):
    enter_func_name = "mlx5_rx_burst_vec_enter"
    exit_func_name = "mlx5_rx_burst_vec_exit"
    #func_name = "mlx5_rx_burst_vec"
    event = b[exit_func_name + "_events"].event(data)

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
    fp_w = open('rx_log.txt', 'a')
    fp_w.write(str(event.count) + ' ' + func_name + ' ' + str((event.ts - data_list[enter_func_name][event.pid][event.count]) / divide_num_sec) + '\n')
    fp_w.close() 


def rxq_cq_decompress_v_enter_event(cpu, data, size):
    func_name = "rxq_cq_decompress_v_enter"
    event = b[func_name + "_events"].event(data)

    exist = data_list.get(func_name)
    if exist == None:
        data_list[func_name] = {}
    exist = data_list[func_name].get(event.pid)
    if exist == None:
        data_list[func_name][event.pid] = {}

    if data_list[func_name][event.pid].get(event.count) : return
    data_list[func_name][event.pid][event.count] = event.ts

def rxq_cq_decompress_v_exit_event(cpu, data, size):
    enter_func_name = "rxq_cq_decompress_v_enter"
    exit_func_name = "rxq_cq_decompress_v_exit"
    func_name = "rxq_cq_decompress_v"
    event = b[exit_func_name + "_events"].event(data)

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
    fp_w = open('rx_log.txt', 'a')
    fp_w.write(str(event.count) + ' ' + func_name + ' ' + str((event.ts - data_list[enter_func_name][event.pid][event.count]) / divide_num_sec) + '\n')
    fp_w.close() 

def rxq_cq_process_v_enter_event(cpu, data, size):
    func_name = "rxq_cq_process_v_enter"
    event = b[func_name + "_events"].event(data)

    exist = data_list.get(func_name)
    if exist == None:
        data_list[func_name] = {}
    exist = data_list[func_name].get(event.pid)
    if exist == None:
        data_list[func_name][event.pid] = {}

    if data_list[func_name][event.pid].get(event.count) : return
    data_list[func_name][event.pid][event.count] = event.ts

def rxq_cq_process_v_exit_event(cpu, data, size):
    enter_func_name = "rxq_cq_process_v_enter"
    exit_func_name = "rxq_cq_process_v_exit"
    func_name = "rxq_cq_process_v"
    event = b[exit_func_name + "_events"].event(data)

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
    fp_w = open('rx_log.txt', 'a')
    fp_w.write(str(event.count) + ' ' + func_name + ' ' + str((event.ts - data_list[enter_func_name][event.pid][event.count]) / divide_num_sec) + '\n')
    fp_w.close() 


def mlx5_rx_burst_mprq_vec_enter_event(cpu, data, size):    
    func_name = "mlx5_rx_burst_mprq_vec_enter"
    event = b[func_name + "_events"].event(data)

    exist = data_list.get(func_name)
    if exist == None:
        data_list[func_name] = {}
    exist = data_list[func_name].get(event.pid)
    if exist == None:
        data_list[func_name][event.pid] = {}

    if data_list[func_name][event.pid].get(event.count) : return
    data_list[func_name][event.pid][event.count] = event.ts

def mlx5_rx_burst_mprq_vec_exit_event(cpu, data, size):
    enter_func_name = "mlx5_rx_burst_mprq_vec_enter"
    exit_func_name = "mlx5_rx_burst_mprq_vec_exit"
    func_name = "mlx5_rx_burst"
    event = b[exit_func_name + "_events"].event(data)

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
    fp_w = open('rx_log.txt', 'a')
    fp_w.write(str(event.count) + ' ' + func_name + ' ' + str((event.ts - data_list[enter_func_name][event.pid][event.count]) / divide_num_sec) + '\n')
    fp_w.close() 

# loop with callback to print_event
b["mlx5_rx_burst_enter_events"].open_perf_buffer(mlx5_rx_burst_enter_event)
b["mlx5_rx_burst_vec_enter_events"].open_perf_buffer(mlx5_rx_burst_vec_enter_event)
b["mlx5_rx_burst_mprq_vec_enter_events"].open_perf_buffer(mlx5_rx_burst_mprq_vec_enter_event)
b["rxq_cq_decompress_v_enter_events"].open_perf_buffer(rxq_cq_decompress_v_enter_event)
b["rxq_cq_process_v_enter_events"].open_perf_buffer(rxq_cq_process_v_enter_event)

b["mlx5_rx_burst_exit_events"].open_perf_buffer(mlx5_rx_burst_exit_event)
b["mlx5_rx_burst_vec_exit_events"].open_perf_buffer(mlx5_rx_burst_vec_exit_event)
b["mlx5_rx_burst_mprq_vec_exit_events"].open_perf_buffer(mlx5_rx_burst_mprq_vec_exit_event)
b["rxq_cq_decompress_v_exit_events"].open_perf_buffer(rxq_cq_decompress_v_exit_event)
b["rxq_cq_process_v_exit_events"].open_perf_buffer(rxq_cq_process_v_exit_event)
b["rte_eth_dev_count_avail_exit_events"].open_perf_buffer(rte_eth_dev_count_avail_exit_event)
b["rte_pktmbuf_pool_create_exit_events"].open_perf_buffer(rte_pktmbuf_pool_create_exit_event)

def print_latency():
    print('save log start')
    for data in log_list:
        fp.write(str(data[0]) + ' ' + str(data[1]) + ' ' + str(float(data[2] / divide_num_sec)) + '\n')
    print('save log end')

while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        #print_latency()
        exit()
