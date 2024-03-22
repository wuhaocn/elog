# 常见的钩子
在Linux系统中，eBPF（Extended Berkeley Packet Filter）可以与不同的钩子（hooks）结合使用，以在系统中的不同位置执行自定义程序。以下是一些常见的钩子和它们的用途：

## list
* list
    *  XDP（eXpress Data Path）
    *  tc（Traffic Control）
    *  sk_skb
    *  tracepoint
    *  kprobe/kretprobe
    *  uprobe/uretprobe
* table
### 钩子 SEC 标记列表

| 类型             | SEC 标记                                   | 描述                                                          |
|-----------------|-------------------------------------------|---------------------------------------------------------------|
| XDP             | SEC("xdp")                                | XDP 数据包处理钩子。                                           |
| XDP             | SEC("xdp_rx")                             | XDP 接收钩子。                                                 |
| XDP             | SEC("xdp_tx")                             | XDP 发送钩子。                                                 |
| XDP             | SEC("xdp_md")                             | XDP 元数据钩子。                                               |
| XDP             | SEC("xdp_md_end")                         | XDP 元数据末尾钩子。                                           |
| TC              | SEC("tc")                                 | 用于在 TC 操作期间进行数据包处理。                             |
| TC              | SEC("tc_ingress")                         | 用于在 TC 入口点进行数据包处理。                               |
| TC              | SEC("tc_egress")                          | 用于在 TC 出口点进行数据包处理。                               |
| sk_skb          | SEC("sk_skb/stream_parser")               | 用于在流式传输的套接字上进行数据包处理。                        |
| sk_skb          | SEC("sk_skb/udp_parser")                  | 用于在 UDP 套接字上进行数据包处理。                            |
| sk_skb          | SEC("sk_skb/tcp_parser")                  | 用于在 TCP 套接字上进行数据包处理。                            |
| sk_skb          | SEC("sk_skb/raw_parser")                  | 用于在原始套接字上进行数据包处理。                             |
| tracepoint      | SEC("tracepoint/syscalls/sys_enter_open") | 在 sys_enter_open tracepoint 触发时执行的处理逻辑。            |
| tracepoint      | SEC("tracepoint/sched/sched_switch")      | 在 sched_switch tracepoint 触发时执行的处理逻辑。              |
| tracepoint      | SEC("tracepoint/irq/irq_handler_entry")   | 在 irq_handler_entry tracepoint 触发时执行的处理逻辑。        |
| tracepoint      | SEC("tracepoint/block/block_rq_insert")   | 在 block_rq_insert tracepoint 触发时执行的处理逻辑。           |
| tracepoint      | SEC("tracepoint/net/netif_receive_skb")   | 在 netif_receive_skb tracepoint 触发时执行的处理逻辑。        |
| kprobe/kretprobe| SEC("kprobe:my_function")                | 在 my_function 函数执行前触发的处理逻辑。                      |
| kprobe/kretprobe| SEC("kprobe:my_function+offset")         | 在 my_function 函数中指定偏移量处执行前触发的处理逻辑。        |
| kprobe/kretprobe| SEC("kprobe:my_module:my_function")      | 在指定内核模块 my_module 中的 my_function 函数执行前触发的处理逻辑。|
| kprobe/kretprobe| SEC("kprobe:my_module:my_function+offset")| 在指定内核模块 my_module 中的 my_function 函数中指定偏移量处执行前触发的处理逻辑。|
| kprobe/kretprobe| SEC("kretprobe:my_function")             | 在 my_function 函数返回前触发的处理逻辑。                      |
| kprobe/kretprobe| SEC("kretprobe:my_function+offset")      | 在 my_function 函数中指定偏移量处返回前触发的处理逻辑。        |
| kprobe/kretprobe| SEC("kretprobe:my_module:my_function")   | 在指定内核模块 my_module 中的 my_function 函数返回前触发的处理逻辑。|
| kprobe/kretprobe| SEC("kretprobe:my_module:my_function+offset") | 在指定内核模块 my_module 中的 my_function 函数中指定偏移量处返回前触发的处理逻辑。|
| uprobe/uretprobe| SEC("uprobe:/path/to/binary:function")    | 在指定二进制文件中的指定函数调用前触发的处理逻辑。             |
| uprobe/uretprobe| SEC("uprobe:/path/to/binary:*")          | 在指定二进制文件中的所有函数调用前触发的处理逻辑。             |
| uprobe/uretprobe| SEC("uprobe://path/to/binary:offset")    | 在指定二进制文件中的指定偏移量处调用前触发的处理逻辑。         |
| uprobe/uretprobe| SEC("uprobe://path/to/binary:*")          | 在指定二进制文件中的所有偏移量处调用前触发的处理逻辑。         |
| uprobe/uretprobe| SEC("uretprobe:/path/to/binary:function")| 在指定二进制文件中的指定函数返回前触发的处理逻辑。             |
| uprobe/uretprobe| SEC("uretprobe:/path/to/binary:*")       | 在指定二进制文件中的所有函数返回前触发的处理逻辑。             |
| uprobe/uretprobe| SEC("uretprobe://path/to/binary:offset") | 在指定二进制文件中的指定偏移量处返回前触发的处理逻辑。         |
| uprobe/uretprobe| SEC("uretprobe://path/to/binary:*")       | 在指定二进制文件中的所有偏移量处返回前触发的处理逻辑。         |


## XDP（eXpress Data Path）：

用途：XDP钩子位于网络设备的接收路径上，允许在数据包到达网络设备时进行高性能的数据包处理。通常用于实现数据包过滤、转发、DDoS防护等功能。
XDP（eXpress Data Path）是一种高性能的数据包处理技术，可以在网络设备的接收路径上进行数据包处理。在 XDP 中，使用 eBPF（extended Berkeley Packet Filter）来编写数据包处理逻辑，并使用 SEC 标记来定义处理逻辑的触发点。以下是一些常见的 XDP SEC 标记定义：

### simple
```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_drop(struct xdp_md *ctx) { 
    // 丢弃所有数据包
    return XDP_DROP;
}

```

### XDP 钩子 SEC 标记

* `SEC("xdp")` - 用于在 XDP 操作期间进行数据包处理。这个标记定义的程序会在数据包经过 XDP 子系统时触发，用于高性能数据包处理和转发。

* `SEC("xdp_rx")` - 用于在数据包接收阶段进行处理，类似于 XDP 操作期间的预处理。
* `SEC("xdp_tx")` - 用于在数据包发送阶段进行处理，类似于 XDP 操作期间的后处理。

* `SEC("xdp_redirect")` - 用于在 XDP 操作期间进行数据包重定向处理。这个标记定义的程序可以将数据包重定向到其他网络接口或内核模块。

* `SEC("xdp_exception")` - 用于在 XDP 操作期间进行异常数据包处理。这个标记定义的程序可以处理由 XDP 操作引起的异常情况。

* `SEC("xdp_cpumap_enqueue")` - 用于在 XDP 操作期间将数据包发送到 CPU map 中进行处理。这个标记定义的程序可以将数据包发送到特定的 CPU 上进行处理。

* `SEC("xdp_devmap_xmit")` - 用于在 XDP 操作期间将数据包发送到设备映射（devmap）中进行处理。这个标记定义的程序可以将数据包发送到设备映射中的其他网络接口上。

* `SEC("xdp_skb")` - 用于在 XDP 操作期间进行数据包处理，并且需要传递 skb 数据结构。这个标记定义的程序可以直接操作 skb 数据结构进行数据包处理。

* `SEC("xdp_md")` - 用于在 XDP 操作期间进行数据包处理，并且需要传递 xdp_md 数据结构。这个标记定义的程序可以访问和修改 xdp_md 数据结构中的信息进行数据包处理。

* `SEC("xdp_dummy")` - 用于在 XDP 操作期间进行虚拟的无操作处理。这个标记定义的程序不会对数据包进行任何实际处理，可以用于测试和调试。

* `SEC("xdp_user")` - 用于在 XDP 操作期间进行用户自定义的处理逻辑。这个标记定义的程序可以根据具体需求实现各种自定义的数据包处理功能。


## tc（Traffic Control）
用途：tc钩子允许在Linux内核中的Traffic Control子系统中执行eBPF程序，以实现对网络流量的控制和管理。通常用于实现QoS（Quality of Service）、流量整形、过滤等功能。

Traffic Control（TC）是 Linux 内核中用于网络流量控制和管理的子系统，它允许用户对网络流量进行各种操作，如限速、队列管理、过滤、分类等。在使用 eBPF 来扩展 TC 功能时，可以使用不同的 SEC 标记来定义 eBPF 程序的入口点。以下是一些常见的 TC SEC 标记定义：

### simple
```c
#include <linux/bpf.h>
#include <linux/pkt_cls.h>

SEC("tc_ingress")
int ingress_filter(struct __sk_buff *skb) {
    // 在入口点进行流量控制逻辑处理
    return TC_ACT_OK; // 返回 TC_ACT_OK 表示允许通过
}
```


### TC 钩子 SEC 标记

* `SEC("tc")` - 用于在 TC 操作期间进行数据包处理。这个标记定义的程序会在数据包经过 TC 子系统时触发，可以用于实现各种 TC 功能，如限速、队列管理、过滤、分类等。

* `SEC("tc_ingress")` - 用于在 TC 入口点进行数据包处理。这个标记定义的程序会在数据包进入 TC 入口点时触发，可以用于实现流量控制和管理。

* `SEC("tc_egress")` - 用于在 TC 出口点进行数据包处理。这个标记定义的程序会在数据包离开 TC 出口点时触发，可以用于实现流量控制和管理。

* `SEC("tc_clsact")` - 用于在 TC 类别操作器（clsact）上进行数据包处理。这个标记定义的程序会在数据包经过 TC 类别操作器时触发，用于实现数据包分类和过滤功能。

* `SEC("tc_ingress_reclassify")` - 用于在 TC 入口点进行数据包重新分类处理。这个标记定义的程序会在数据包进入 TC 入口点时触发，并且需要重新对数据包进行分类。

* `SEC("tc_egress_reclassify")` - 用于在 TC 出口点进行数据包重新分类处理。这个标记定义的程序会在数据包离开 TC 出口点时触发，并且需要重新对数据包进行分类。

## sk_skb

用途：sk_skb钩子允许在Linux内核中的套接字层执行eBPF程序，以实现对套接字缓冲区的访问和处理。通常用于实现套接字级别的过滤、监控等功能。
sk_skb 是一种 eBPF SEC 标记，用于处理套接字接收到的数据包。

### simple

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

SEC("sk_skb/stream_parser")
int stream_parser(struct __sk_buff *skb) {
    // 在流式传输的套接字上进行数据包处理
    return 0;
}

SEC("sk_skb/udp_parser")
int udp_parser(struct __sk_buff *skb) {
    // 在 UDP 套接字上进行数据包处理
    return 0;
}

SEC("sk_skb/tcp_parser")
int tcp_parser(struct __sk_buff *skb) {
    // 在 TCP 套接字上进行数据包处理
    return 0;
}

SEC("sk_skb/raw_parser")
int raw_parser(struct __sk_buff *skb) {
    // 在原始套接字上进行数据包处理
    return 0;
}
```
### sk_skb 钩子 SEC 标记

* `SEC("sk_skb/stream_parser")` - 用于在流式传输的套接字上进行数据包处理。
* `SEC("sk_skb/udp_parser")` - 用于在 UDP 套接字上进行数据包处理。
* `SEC("sk_skb/tcp_parser")` - 用于在 TCP 套接字上进行数据包处理。
* `SEC("sk_skb/raw_parser")` - 用于在原始套接字上进行数据包处理。


## tracepoint：

用途：tracepoint钩子允许在Linux内核的跟踪事件中执行eBPF程序，以实现对内核中各种事件的跟踪和监控。通常用于调试、性能分析等目的。
tracepoint 是一种 eBPF SEC 标记，用于跟踪内核中的跟踪点。

### simple

```c
#include <linux/bpf.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct tracepoint__syscalls__sys_enter_execve *args) {
    // 在 execve 系统调用进入跟踪点时触发的处理逻辑
    return 0;
}

SEC("tracepoint/sched/sched_switch")
int trace_sched_switch(struct tracepoint__sched__sched_switch *args) {
    // 在调度切换跟踪点时触发的处理逻辑
    return 0;
}
```
### Tracepoint 钩子 SEC 标记

* `SEC("tracepoint/syscalls/sys_enter_open")` - 用于在 sys_enter_open tracepoint 触发时执行的处理逻辑。
* `SEC("tracepoint/sched/sched_switch")` - 用于在 sched_switch tracepoint 触发时执行的处理逻辑。
* `SEC("tracepoint/irq/irq_handler_entry")` - 用于在 irq_handler_entry tracepoint 触发时执行的处理逻辑。
* `SEC("tracepoint/block/block_rq_insert")` - 用于在 block_rq_insert tracepoint 触发时执行的处理逻辑。
* `SEC("tracepoint/net/netif_receive_skb")` - 用于在 netif_receive_skb tracepoint 触发时执行的处理逻辑。


### simple

```c
#include <linux/bpf.h>

SEC("kprobe/vfs_read")
int kprobe_vfs_read(struct pt_regs *ctx) {
    // 在 vfs_read 函数调用前触发的处理逻辑
    return 0;
}

SEC("kretprobe/vfs_read")
int kretprobe_vfs_read(struct pt_regs *ctx) {
    // 在 vfs_read 函数返回前触发的处理逻辑
    return 0;
}
```
### Kprobe/Kretprobe 钩子与 SEC 标记


#### Kprobe 钩子 SEC 标记

* `SEC("kprobe:my_function")` - 用于在 my_function 函数执行前触发的处理逻辑。
* `SEC("kprobe:my_function+offset")` - 用于在 my_function 函数中指定偏移量处执行前触发的处理逻辑。
* `SEC("kprobe:my_module:my_function")` - 用于在指定内核模块 my_module 中的 my_function 函数执行前触发的处理逻辑。
* `SEC("kprobe:my_module:my_function+offset")` - 用于在指定内核模块 my_module 中的 my_function 函数中指定偏移量处执行前触发的处理逻辑。

#### Kretprobe 钩子 SEC 标记

* `SEC("kretprobe:my_function")` - 用于在 my_function 函数返回前触发的处理逻辑。
* `SEC("kretprobe:my_function+offset")` - 用于在 my_function 函数中指定偏移量处返回前触发的处理逻辑。
* `SEC("kretprobe:my_module:my_function")` - 用于在指定内核模块 my_module 中的 my_function 函数返回前触发的处理逻辑。
* `SEC("kretprobe:my_module:my_function+offset")` - 用于在指定内核模块 my_module 中的 my_function 函数中指定偏移量处返回前触发的处理逻辑。



## uprobe/uretprobe：
uprobe 和 uretprobe 是一种 eBPF SEC 标记，用于跟踪用户空间程序中函数的调用和返回。
用途：uprobe和uretprobe钩子允许在用户空间程序的函数入口和出口处执行eBPF程序，以实现对用户空间程序的跟踪和监控。通常用于分析应用程序行为、性能调优等目的。


### simple

```c
#include <linux/bpf.h>

SEC("uprobe:/lib/libc.so.6:malloc")
int uprobe_malloc(struct pt_regs *ctx) {
    // 在 libc.so.6 中的 malloc 函数调用前触发的处理逻辑
    return 0;
}

SEC("uretprobe:/lib/libc.so.6:malloc")
int uretprobe_malloc(struct pt_regs *ctx) {
    // 在 libc.so.6 中的 malloc 函数返回前触发的处理逻辑
    return 0;
}
```

### list

* *Uprobe/Uretprobe 钩子与 SEC 标记

#### Uprobe 钩子 SEC 标记

* `SEC("uprobe:/path/to/binary:function")` - 用于在指定二进制文件中的指定函数调用前触发的处理逻辑。
* `SEC("uprobe:/path/to/binary:*")` - 用于在指定二进制文件中的所有函数调用前触发的处理逻辑。
* `SEC("uprobe://path/to/binary:offset")` - 用于在指定二进制文件中的指定偏移量处调用前触发的处理逻辑。
* `SEC("uprobe://path/to/binary:*")` - 用于在指定二进制文件中的所有偏移量处调用前触发的处理逻辑。

#### Uretprobe 钩子 SEC 标记

* `SEC("uretprobe:/path/to/binary:function")` - 用于在指定二进制文件中的指定函数返回前触发的处理逻辑。
* `SEC("uretprobe:/path/to/binary:*")` - 用于在指定二进制文件中的所有函数返回前触发的处理逻辑。
* `SEC("uretprobe://path/to/binary:offset")` - 用于在指定二进制文件中的指定偏移量处返回前触发的处理逻辑。
* `SEC("uretprobe://path/to/binary:*")` - 用于在指定二进制文件中的所有偏移量处返回前触发的处理逻辑。

