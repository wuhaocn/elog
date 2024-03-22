# ebpf
## desc
eBPF 是什么呢？ 从它的全称“扩展的伯克利数据包过滤器 (Extended Berkeley Packet Filter)
BPF 提供了一种在内核事件和用户程序事件发生时安全注入代码的机制，这就让非内核开发人员也可以对内核进行控制。随着内核的发展，BPF 逐步从最初的数据包过滤扩展到了网络、内核、安全、跟踪等，而且它的功能特性还在快速发展中，这种扩展后的 BPF 被简称为 eBPF（相应的，早期的 BPF 被称为经典 BPF，简称 cBPF）。实际上，现代内核所运行的都是 eBPF，如果没有特殊说明，内核和开源社区中提到的 BPF 等同于 eBPF。

## func
SEC标记用于定义eBPF程序的附加信息，指定程序应该附加到哪个内核钩子点。以下是一些常见的SEC类型或钩子点类别：
* 网络钩子点：
    socket_ops：与套接字操作相关的钩子点。
    xdp：用于数据包处理的XDP（eXpress Data Path）钩子点。
* 跟踪钩子点：
    kprobe/*：用于在任何内核函数入口点附加的通用kprobe钩子点。
    tracepoint/*：用于跟踪内核中特定事件的钩子点，例如系统调用、网络事件和调度事件。
* 安全钩子点：
与Linux Security Modules（LSM）相关的钩子点，例如lsm/socket_create、lsm/socket_bind等。
* 性能分析钩子点：
    uprobe/*：附加在用户空间函数上的uprobe钩子点，用于性能分析。
    fentry/*和fexit/*：分别用于函数入口和出口的钩子点。
* 其他钩子点：
    raw_tracepoint/*：原始跟踪点，允许更细粒度的跟踪。
    perf_event：用于性能事件的钩子点。
    请注意，这些仅是一些常见的钩子点示例。实际上，可用的SEC类型和钩子点远不止这些，具体取决于内核版本和配置。要了解更详细的信息，请参阅您使用的Linux内核版本的官方文档或源代码。同时，确保在使用eBPF时充分理解所选择的钩子点的含义和潜在影响，以确保系统的稳定性和性能。
![alt text](https://ebpf.io/static/e293240ecccb9d506587571007c36739/691bc/overview.webp)
## demo
refer: https://ebpf.io/


### 入门文档

包含简单的 eBPF 程序样例与介绍，这部分主要使用 `eunomia-bpf` 框架简化开发，并介绍了 eBPF 的基本使用方式和开发流程。

- [lesson 0-introduce](src/0-introduce/README.md) 介绍 eBPF 的基本概念和常见的开发工具
- [lesson 1-helloworld](src/1-helloworld/README.md) 使用 eBPF 开发最简单的「Hello World」程序，介绍 eBPF 的基本框架和开发流程
- [lesson 2-kprobe-unlink](src/2-kprobe-unlink/README.md) 在 eBPF 中使用 kprobe 捕获 unlink 系统调用
- [lesson 3-fentry-unlink](src/3-fentry-unlink/README.md) 在 eBPF 中使用 fentry 捕获 unlink 系统调用
- [lesson 4-opensnoop](src/4-opensnoop/README.md) 使用 eBPF 捕获进程打开文件的系统调用集合，使用全局变量在 eBPF 中过滤进程 pid
- [lesson 5-uprobe-bashreadline](src/5-uprobe-bashreadline/README.md) 在 eBPF 中使用 uprobe 捕获 bash 的 readline 函数调用
- [lesson 6-sigsnoop](src/6-sigsnoop/README.md) 捕获进程发送信号的系统调用集合，使用 hash map 保存状态
- [lesson 7-execsnoop](src/7-execsnoop/README.md) 捕获进程执行时间，通过 perf event array 向用户态打印输出
- [lesson 8-execsnoop](src/8-exitsnoop/README.md) 捕获进程退出事件，使用 ring buffer 向用户态打印输出
- [lesson 9-runqlat](src/9-runqlat/README.md) 捕获进程调度延迟，以直方图方式记录
- [lesson 10-hardirqs](src/10-hardirqs/README.md) 使用 hardirqs 或 softirqs 捕获中断事件

### 进阶文档和示例

我们开始主要基于 `libbpf` 构建完整的 eBPF 工程，并且把它和各种应用场景结合起来进行实践。

- [lesson 11-bootstrap](src/11-bootstrap/README.md) 使用 libbpf-boostrap 为 eBPF 编写原生的 libbpf 用户态代码，并建立完整的 libbpf 工程。
- [lesson 12-profile](src/12-profile/README.md) 使用 eBPF 进行性能分析
- [lesson 13-tcpconnlat](src/13-tcpconnlat/README.md) 记录 TCP 连接延迟，并使用 libbpf 在用户态处理数据
- [lesson 14-tcpstates](src/14-tcpstates/README.md) 记录 TCP 连接状态与 TCP RTT
- [lesson 15-javagc](src/15-javagc/README.md) 使用 usdt 捕获用户态 Java GC 事件耗时
- [lesson 16-memleak](src/16-memleak/README.md) 检测内存泄漏
- [lesson 17-biopattern](src/17-biopattern/README.md) 捕获磁盘 IO 模式
- [lesson 18-further-reading](src/18-further-reading/README.md) 更进一步的相关资料：论文列表、项目、博客等等
- [lesson 19-lsm-connect](src/19-lsm-connect/README.md) 使用 LSM 进行安全检测防御
- [lesson 20-tc](src/20-tc/README.md) 使用 eBPF 进行 tc 流量控制
- [lesson 21-xdp](src/21-xdp/README.md) 使用 eBPF 进行 XDP 报文处理

### 高级主题

这里涵盖了一系列和 eBPF 相关的高级内容，包含在 Android 上使用 eBPF 程序、使用 eBPF 程序进行可能的攻击与防御、复杂的追踪等等。将 eBPF 用户态与内核态的部分结合起来，可能能带来巨大的威力（同时也是安全隐患）。这部分较为复杂的示例会基于 libbpf、Cilium 等框架进行开发，简单示例使用 eunomia-bpf 完成。

Android:

- [在 Android 上使用 eBPF 程序](src/22-android/README.md)

网络和追踪：

- [使用 uprobe 捕获多种库的 SSL/TLS 明文数据](src/30-sslsniff/README.md)
- [使用 eBPF socket filter 或 syscall trace 追踪 HTTP 请求和其他七层协议](src/23-http/README.md)
- [使用 sockops 加速网络请求转发](src/29-sockops/README.md)

安全：

- [使用 eBPF 修改系统调用参数](src/34-syscall/README.md)
- [使用 eBPF 隐藏进程或文件信息](src/24-hide/README.md)
- [使用 bpf_send_signal 发送信号终止进程](src/25-signal/README.md)
- [使用 eBPF 添加 sudo 用户](src/26-sudo/README.md)
- [使用 eBPF 替换任意程序读取或写入的文本](src/27-replace/README.md)
- [BPF 的生命周期：使用 Detached 模式在用户态应用退出后持续运行 eBPF 程序](src/28-detach/README.md)
- [eBPF 运行时的安全性与面临的挑战](src/18-further-reading/ebpf-security.zh.md)

其他高级特性：

- [eBPF开发实践：使用 user ring buffer 向内核异步发送信息](src/35-user-ringbuf/README.md)
- [用户空间 eBPF 运行时：深度解析与应用实践](src/36-userspace-ebpf/README.md)
- [借助 eBPF 和 BTF，让用户态也能一次编译、到处运行](src/38-btf-uprobe/README.md)

# env
### tool
git vscode go
### lib
在 Ubuntu/Debian 上，你需要执行以下命令：

```shell
sudo apt install clang libelf1 libelf-dev zlib1g-dev
```

在 CentOS/Fedora 上，你需要执行以下命令：

```shell
sudo dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```

# issues
## header not found

```
/usr/include/linux/types.h:5:10: fatal error: 'asm/types.h' file not found
```

```
ln -s  /usr/include/aarch64-linux-gnu/asm /usr/include/asm
```