package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
)
const (
    CONNECT     = 1
    CONNACK     = 2
    PUBLISH     = 3
    PUBACK      = 4
    PUBREC      = 5
    PUBREL      = 6
    PUBCOMP     = 7
    SUBSCRIBE   = 8
    SUBACK      = 9
    UNSUBSCRIBE = 10
    UNSUBACK    = 11
    PINGREQ     = 12
    PINGRESP    = 13
    DISCONNECT  = 14
)


func logHeader(){
    log.Printf("%-15s %-6s -> %-15s %-6s %-15s %-6s %-8s %-6s %-11s %-8s %-6s %-9s %-10s",
		"Src addr",
		"Port",
		"Dest addr",
		"Port",
		"CurTime",
        "SRtt",
		"NetProto",
		"NetCmd",
        "NetPkgLegth",
		"AppProto",
		"AppCmd",
        "AppLength",
        "PlayLoad",
	)
}

func logEvent(event bpfEvent){
    payloadStr := "" // 初始化为空字符串
    for _, v := range event.Payload {
        payloadStr += fmt.Sprintf("%02x ", uint8(v)) // 将整数转换为16进制字符串
    }
    log.Printf("%-15s %-6d -> %-15s %-6d %-15d %-6d %-8d %-6d %-11d %-8d %-6d %-9d %-10s",
        intToIP(event.Saddr),
        event.Sport,
        intToIP(event.Daddr),
        event.Dport,
        event.Curtime,
        event.Srtt,
        event.Netproto,
        event.Netcmd,
        event.Netpkglength,
        event.Appproto,
        event.Appcmd,
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
func mqttCmdToString(cmd uint32) string {
    switch cmd {
    case CONNECT:
        return "CONNECT"
    case CONNACK:
        return "CONNACK"
    case PUBLISH:
        return "PUBLISH"
    case PUBACK:
        return "PUBACK"
    case PUBREC:
        return "PUBREC"
    case PUBREL:
        return "PUBREL"
    case PUBCOMP:
        return "PUBCOMP"
    case SUBSCRIBE:
        return "SUBSCRIBE"
    case SUBACK:
        return "SUBACK"
    case UNSUBSCRIBE:
        return "UNSUBSCRIBE"
    case UNSUBACK:
        return "UNSUBACK"
    case PINGREQ:
        return "PINGREQ"
    case PINGRESP:
        return "PINGRESP"
    case DISCONNECT:
        return "DISCONNECT"
    default:
        return "UNKNOWN"
    }
}


// 将 netflags 的 uint8 值转换为字符串表示
func netflagsToString(flags uint8) string {
    var flagStrings []string

    if flags&1 != 0 {
        flagStrings = append(flagStrings, "SYN")
    }
    if flags&2 != 0 {
        flagStrings = append(flagStrings, "ACK")
    }
    if flags&4 != 0 {
        flagStrings = append(flagStrings, "FIN")
    }
    if flags&8 != 0 {
        flagStrings = append(flagStrings, "RST")
    }
    if flags&16 != 0 {
        flagStrings = append(flagStrings, "PSH")
    }
    if flags&32 != 0 {
        flagStrings = append(flagStrings, "URG")
    }

    return strings.Join(flagStrings, ", ")
}

