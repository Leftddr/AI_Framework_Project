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
// define output data structure in C
struct data_t {
    u64 count;
    u32 pid;
    u64 ts;
};
struct ret_data{
    u64 retval;
};
//This is part of the recommended mechanism for transferring per-event data from kernel to user space.
BPF_PERF_OUTPUT(mlx5_tx_burst_none_empw_events);
BPF_PERF_OUTPUT(mlx5_tx_burst_i_empw_events);
BPF_PERF_OUTPUT(mlx5_tx_handle_completion_events);
BPF_PERF_OUTPUT(__mlx5_tx_free_mbuf_events);
BPF_PERF_OUTPUT(rte_lcore_count_events);
BPF_HASH(current_count, u64);

#define KEY 1234

int rte_lcore_count_latency(struct pt_regs *ctx){
    struct ret_data data = {};
    int retval = PT_REGS_RC(ctx);

    data.retval = retval;
    rte_lcore_count_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int mlx5_tx_burst_none_empw_latency(struct pt_regs *ctx){
    struct data_t data = {};
    u64 key = KEY, *curr, zero = 0;

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    curr = current_count.lookup_or_try_init(&key, &zero);
    if(curr == NULL) return 0;

    data.count = (*curr)++;
    current_count.update(&key, curr);
    //for submitting custom event data to user space
    mlx5_tx_burst_none_empw_events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int mlx5_tx_burst_i_empw_latency(struct pt_regs *ctx){
   struct data_t data = {};
   u64 key = KEY, *curr, zero = 0;

   data.pid = bpf_get_current_pid_tgid();
   data.ts = bpf_ktime_get_ns();
   curr = current_count.lookup_or_try_init(&key, &zero);
   if(curr == NULL) return 0;
   
   data.count = (*curr)++;
   current_count.update(&key, curr);
   mlx5_tx_burst_i_empw_events.perf_submit(ctx, &data, sizeof(data));
}


int mlx5_tx_handle_completion_latency(struct pt_regs *ctx){
    struct data_t data = {};
    u64 key = KEY, *curr, zero = 0;

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    curr = current_count.lookup_or_try_init(&key, &zero);
    if(curr == NULL) return 0;
    data.count = (*curr);
    //for submitting custom event data to user space
    mlx5_tx_handle_completion_events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int __mlx5_tx_free_mbuf_latency(struct pt_regs *ctx){
    struct data_t data = {};
    u64 key = KEY, *curr, zero = 0;

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    curr = current_count.lookup_or_try_init(&key, &zero);
    if(curr == NULL) return 0;
    data.count = (*curr);
    __mlx5_tx_free_mbuf_events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""
@dataclass
class latency_data:
    name : str = None
    time : float = None
@dataclass
class ret_data:
    retval : int = None
'''
list_none_empw = []
list_handle_completion = []
'''	
# DPDK의 공유라이브러리의 위치이다.
shared_library_path="/usr/local/lib/x86_64-linux-gnu/"
# shared_library_path="/opt/mellanox/dpdk/lib/x86_64-linux-gnu/"
# load BPF program
# DPDK를 운용할 때 기본 설정을 위한 함수들이다.
b = BPF(text=prog)
b.attach_uprobe(name=shared_library_path+"librte_net_mlx5.so", sym="mlx5_tx_burst_none_empw", fn_name="mlx5_tx_burst_none_empw_latency")
b.attach_uprobe(name=shared_library_path+"librte_net_mlx5.so", sym="mlx5_tx_handle_completion", fn_name="mlx5_tx_handle_completion_latency")
b.attach_uprobe(name=shared_library_path+"librte_net_mlx5.so", sym="mlx5_tx_burst_i_empw", fn_name="mlx5_tx_burst_i_empw_latency")
b.attach_uprobe(name=shared_library_path+"librte_net_mlx5.so", sym="__mlx5_tx_free_mbuf", fn_name="__mlx5_tx_free_mbuf_latency")
b.attach_uretprobe(name=shared_library_path+"librte_eal.so", sym="rte_lcore_count", fn_name="rte_lcore_count_latency")
'''
# process event
mlx5_tx_burst_none_empw_st = {}
mlx5_tx_handle_completion_st = {}
'''
list_tx_process_name = ["mlx5_tx_burst_none_empw", "mlx5_tx_handle_completion", "__mlx5_tx_free_mbuf", "mlx5_tx_burst_i_empw", "rte_lcore_count"]
data_list = {}
process_event = {}

# 함수의 형태는 대거 이렇다.
# 이게 latency를 잴 수 있는 거구나... event가 따라 붙으면서 현재 시간을 얻어오고
# 처음 uprobe가 붙었을 때의 시간을 빼서 구한다.
def mlx5_tx_burst_none_empw_event(cpu, data, size):
    global mlx5_tx_burst_none_empw_st
    # data를 통해 event 변수를 꺼내온다.
    event = b["mlx5_tx_burst_none_empw_events"].event(data)
    exist = process_event["mlx5_tx_burst_none_empw"].get(event.pid)
    time_s = -1
    if exist == None:
        time_s = (float)(event.ts / 1000000000)
    else:
        time_s = (float(event.ts - process_event["mlx5_tx_burst_none_empw"][event.pid])) / 100000000 
    process_event["mlx5_tx_burst_none_empw"][event.pid] = event.ts
    temp_data = latency_data()
    temp_data.name = "mlx5_tx_burst_none_empw"
    temp_data.time = time_s
    temp_data.count = event.count
    data_list["mlx5_tx_burst_none_empw"].append(temp_data)
    '''
    mlx5_tx_burst_none_empw_st[event.pid] = event.ts
    temp_data = latency_data()
    temp_data.name = "mlx5_tx_burst_none_empw"
    temp_data.time = time_s
    list_none_empw.append(temp_data)
    '''
    #printb(b"%-18.9f %-6d %s" % (time_s, event.pid,
    #    b"mlx5_tx_burst_none_empw"))

def mlx5_tx_burst_i_empw_event(cpu, data, size):
    global mlx5_tx_burst_none_empw_st
    # data를 통해 event 변수를 꺼내온다.
    event = b["mlx5_tx_burst_i_empw_events"].event(data)
    exist = process_event["mlx5_tx_burst_i_empw"].get(event.pid)
    time_s = -1
    if exist == None:
        time_s = (float)(event.ts / 1000000000)
    else:
        time_s = (float(event.ts - process_event["mlx5_tx_burst_i_empw"][event.pid])) / 100000000 
    process_event["mlx5_tx_burst_i_empw"][event.pid] = event.ts
    temp_data = latency_data()
    temp_data.name = "mlx5_tx_burst_i_empw"
    temp_data.time = time_s
    temp_data.count = event.count
    data_list["mlx5_tx_burst_i_empw"].append(temp_data)

def mlx5_tx_handle_completion_event(cpu, data, size):
    global mlx5_tx_handle_completion_st
    # data를 통해 event 변수를 꺼내온다.
    event = b["mlx5_tx_handle_completion_events"].event(data)
    time_s = -1
    exist = process_event["mlx5_tx_handle_completion"].get(event.pid)
    if exist == None:
        time_s = (float)(event.ts / 1000000000)
    else:
        time_s = (float(event.ts - process_event["mlx5_tx_handle_completion"][event.pid])) / 1000000000  
    process_event["mlx5_tx_handle_completion"][event.pid] = event.ts
    temp_data = latency_data()
    temp_data.name = "mlx5_tx_handle_completion"
    temp_data.time = time_s
    temp_data.count = event.count
    data_list["mlx5_tx_handle_completion"].append(temp_data)
    '''
    mlx5_tx_handle_completion_st[event.pid] = event.ts
    temp_data = latency_data()
    temp_data.name = "mlx5_tx_handle_completion"
    temp_data.time = time_s
    list_handle_completion.append(temp_data) 
    '''
    #printb(b"%-18.9f %-6d %s" % (time_s, event.pid,
    #    b"mlx5_tx_handle_completion"))

def __mlx5_tx_free_mbuf_event(cpu, data, size):
    global mlx5_tx_handle_completion_st
    # data를 통해 event 변수를 꺼내온다.
    event = b["__mlx5_tx_free_mbuf_events"].event(data)
    time_s = -1
    exist = process_event["__mlx5_tx_free_mbuf"].get(event.pid)
    if exist == None:
        time_s = (float)(event.ts / 1000000000)
    else:
        time_s = (float(event.ts - process_event["__mlx5_tx_free_mbuf"][event.pid])) / 1000000000  
    process_event["__mlx5_tx_free_mbuf"][event.pid] = event.ts
    temp_data = latency_data()
    temp_data.name = "__mlx5_tx_free_mbuf"
    temp_data.time = time_s
    temp_data.count = event.count
    data_list["__mlx5_tx_free_mbuf"].append(temp_data)

def rte_lcore_count_event(cpu, data, size):
    event = b["rte_lcore_count_events"].event(data)
    temp_data = ret_data()
    temp_data.retval = event.retval
    data_list["rte_lcore_count"].append(temp_data)

# loop with callback to print_event
b["mlx5_tx_burst_none_empw_events"].open_perf_buffer(mlx5_tx_burst_none_empw_event)
b["mlx5_tx_handle_completion_events"].open_perf_buffer(mlx5_tx_handle_completion_event)
b["mlx5_tx_burst_i_empw_events"].open_perf_buffer(mlx5_tx_burst_i_empw_event)
b["__mlx5_tx_free_mbuf_events"].open_perf_buffer(__mlx5_tx_free_mbuf_event)
b["rte_lcore_count_events"].open_perf_buffer(rte_lcore_count_event)
#b["mlx5_tx_burst_tmple_events"].open_perf_buffer(mlx5_tx_burst_tmpl_event)
#b["mlx5_tx_burst_mseg_events"].open_perf_buffer(mlx5_tx_burst_mseg_event)
#b["mlx5_tx_burst_tso_events"].open_perf_buffer(mlx5_tx_burst_tso_event)
#b["mlx5_tx_burst_empw_simple_events"].open_perf_buffer(mlx5_tx_burst_empw_simple_event)
#b["mlx5_tx_burst_empw_inline_events"].open_perf_buffer(mlx5_tx_burst_empw_inline_event)
#b["mlx5_tx_burst_single_send_events"].open_perf_buffer(mlx5_tx_burst_single_send_event)

def print_latency():
    f = open('tx_latency.txt', mode = 'wt', encoding = 'utf-8')
    f.write('#count     function	latency(ns)\n')
    f.write(str(data_list["rte_lcore_count"][0].retval) + '\n')
    print('Save data start')
    '''
    for data in list_none_empw:
        f.write(data.name + ' ' + str(data.time) + '\n')
    for data in list_handle_completion:
        f.write(data.name + ' ' + str(data.time) + '\n')
    '''
    for func_name in data_list:
        if func_name == "rte_lcore_count":continue
        for data in data_list[func_name]:
            f.write(str(data.count) + ' ' + data.name + ' ' + str(data.time) + '\n')
    f.close()
    print('Save data end')

for func_name in list_tx_process_name:
    process_event[func_name] = {}
    data_list[func_name] = []

print('Start')
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print_latency()
        exit()
