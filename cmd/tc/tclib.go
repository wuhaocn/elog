package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
)
func logHeader() {
	log.Printf("%-15s %-6s -> %-15s %-6s %-15s %-6s %-8s %-15s %-7s %-10s %-10s %-7s %-10s",
		"Src addr",
		"Port",
		"Dest addr",
		"Port",
		"CurTime",
		"SRtt",
		"NetProto",
		"NetCmd",
		"NetPLen",
		"AppProto",
		"AppCmd",
		"AppPLen",
		"PlayLoad",
	)
}

func logEvent(event bpfEvent) {
	payloadStr := "" // 初始化为空字符串
	for _, v := range event.Payload {
		payloadStr += fmt.Sprintf("%02x ", uint8(v)) // 将整数转换为16进制字符串
	}
	netProtoStr := netprotoToString(event.Netproto) // 转换网络协议为字符串格式
	netCmdStr := netCmdToString(event.Netcmd)       // 转换网络命令为字符串格式
	appProtoStr := appProtoToString(event.Appproto) // 转换应用协议为字符串格式
	appCmdStr := appCmdToString(event.Appcmd)       // 转换应用命令为字符串格式
	log.Printf("%-15s %-6d -> %-15s %-6d %-15d %-6d %-8s %-15s %-7d %-10s %-10s %-7d %-10s",
		intToIP(event.Saddr),
		event.Sport,
		intToIP(event.Daddr),
		event.Dport,
		event.Curtime,
		event.Srtt,
		netProtoStr,
		netCmdStr,
		event.Netpkglength,
		appProtoStr,
		appCmdStr,
		event.Apppkglength,
		payloadStr,
	)
}


// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipNum)
	return ip
}

// netprotoToString converts netproto to string
func netprotoToString(proto uint8) string {
	switch proto {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return "N"
	}
}

// appProtoToString converts appproto to string
func appProtoToString(proto uint8) string {
	switch proto {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 188:
		return "MQTT"
	default:
		return "N"
	}
}

// netCmdToString converts netcmd to string
func netCmdToString(cmd uint8) string {
	var cmdStrings []string
	if cmd&1 != 0 {
		cmdStrings = append(cmdStrings, "SYN")
	}
	if cmd&2 != 0 {
		cmdStrings = append(cmdStrings, "ACK")
	}
	if cmd&4 != 0 {
		cmdStrings = append(cmdStrings, "FIN")
	}
	if cmd&8 != 0 {
		cmdStrings = append(cmdStrings, "RST")
	}
	if cmd&16 != 0 {
		cmdStrings = append(cmdStrings, "PSH")
	}
	if cmd&32 != 0 {
		cmdStrings = append(cmdStrings, "URG")
	}
	return strings.Join(cmdStrings, ", ")
}

// appCmdToString converts appcmd to string based on byte offsets
func appCmdToString(cmd uint8) string {
	switch cmd {
	case 0x10:
		return "CONNECT"
	case 0x20:
		return "CONNACK"
	case 0x30:
		return "PUBLISH"
	case 0x40:
		return "PUBACK"
	case 0x50:
		return "PUBREC"
	case 0x60:
		return "PUBREL"
	case 0x70:
		return "PUBCOMP"
	case 0x82:
		return "SUBSCRIBE"
	case 0x90:
		return "SUBACK"
	case 0xA0:
		return "UNSUBSCRIBE"
	case 0xB0:
		return "UNSUBACK"
	case 0xC0:
		return "PINGREQ"
	case 0xD0:
		return "PINGRESP"
	case 0xE0:
		return "DISCONNECT"
	default:
		return "N"
	}
}
