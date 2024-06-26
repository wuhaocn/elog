package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags "linux" -type event bpf tc.c -- -I../../headers

func main() {
	// Read configuration file
	config, err := readConfig("config/config.yml")
	if err != nil {
		log.Fatalf("Failed to read configuration file: %v", err)
	}
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()
	
	//config port
	updateConfig(config, objs.ProtocolPortsMap)

	ifaceName := os.Args[1]
	attachFilter(ifaceName, objs.bpfPrograms.TcProgFunc)


	rd, err := ringbuf.NewReader(objs.bpfMaps.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	go readLoop(rd)
	// Wait
	<-stopper
}

func updateConfig(config *Config, bpfMap *ebpf.Map) {
	for protocol, ports := range config.Protocol {
		// 如果端口列表长度超过3，则截取前3个端口
		if len(ports) > 3 {
			ports = ports[:3]
		}
		// 创建一个数组，长度为6，用于存储端口号
		value := make([]byte, 6) // 6 字节
		for i, port := range ports {
			offset := i * 2 // 每个端口号占据2个字节
			binary.LittleEndian.PutUint16(value[offset:], uint16(port))
		}
		// 创建固定长度为 16 字节的键
		var key [16]byte
		copy(key[:], protocol)
		// 将协议名称转换为固定大小的字节数组
		err := bpfMap.Put(key[:], value)
		if err != nil {
			log.Fatalf("Failed to put key-value pair to BPF Map: %v", err)
		}
	}
}

func attachFilter(attachTo string, program *ebpf.Program) error {
	devID, err := net.InterfaceByName(attachTo)
	if err != nil {
		return fmt.Errorf("could not get interface ID: %w", err)
	}

	// 出口队列（出口流量）
	qdiscEgress := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: devID.Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	// 入口队列（入口流量）
	qdiscIngress := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: devID.Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	// 替换出口队列
	if err := netlink.QdiscReplace(qdiscEgress); err != nil {
		return fmt.Errorf("could not replace egress qdisc: %w", err)
	}

	// 替换入口队列
	if err := netlink.QdiscReplace(qdiscIngress); err != nil {
		return fmt.Errorf("could not replace ingress qdisc: %w", err)
	}

	// 出口过滤器
	filterEgress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: devID.Index,
			Parent:    netlink.HANDLE_MIN_EGRESS, // 出口流量
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           program.FD(),
		Name:         program.String(),
		DirectAction: true,
	}

	// 入口过滤器
	filterIngress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: devID.Index,
			Parent:    netlink.HANDLE_MIN_INGRESS, // 入口流量
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           program.FD(),
		Name:         program.String(),
		DirectAction: true,
	}
	// 替换出口过滤器
	if err := netlink.FilterReplace(filterEgress); err != nil {
		return fmt.Errorf("failed to replace egress tc filter: %w", err)
	}
	// 替换入口过滤器
	if err := netlink.FilterReplace(filterIngress); err != nil {
		return fmt.Errorf("failed to replace ingress tc filter: %w", err)
	}
	return nil
}


func readLoop(rd *ringbuf.Reader) {
	// bpfSockopsEventf is generated by bpf2go.
	logHeader()
	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.NativeEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}
		logEvent(event);
	}
}


