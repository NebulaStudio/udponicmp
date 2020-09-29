package main

import (
	"flag"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/czxichen/udponicmp"
	"github.com/xtaci/kcp-go"
)

var config = struct {
	host   string
	iface  string
	count  int
	size   int
	server bool
}{}

func init() {
	flag.StringVar(&config.host, "H", "", "服务端地址")
	flag.BoolVar(&config.server, "S", false, "服务端")
	flag.StringVar(&config.iface, "i", "", "使用BPF模式,指定网卡名称")
	flag.IntVar(&config.count, "c", 10, "发送包数")
	flag.IntVar(&config.size, "s", 1500, "单包大小byte,最大2048")
	flag.Parse()
}

func main() {
	if config.server {
		server()
	} else {
		client()
	}
}

func client() {
	packet, err := udponicmp.ListenPacketV4(config.server)
	if err != nil {
		panic(err)
	}
	defer packet.Close()

	addr := &net.UDPAddr{IP: net.ParseIP(config.host), Port: 6789}
	clientsession, err := kcp.NewConn2(addr, nil, 10, 3, packet)
	if err != nil {
		panic(err)
	}
	defer clientsession.Close()

	clientsession.SetWriteBuffer(4 * 1024 * 1024)
	clientsession.SetReadBuffer(4 * 1024 * 1024)
	clientsession.SetWindowSize(1024, 1024)
	clientsession.SetMtu(1350)
	clientsession.SetWriteDelay(false)

	buf := make([]byte, 2048)
	var msg = strings.Repeat("0", config.size)
	for i := 0; i < config.count; i++ {
		now := time.Now()
		_, err = clientsession.Write([]byte(msg))
		if err != nil {
			panic(err)
		}
		n, err := clientsession.Read(buf)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Read %d Consuming: %v\n", n, time.Now().Sub(now))
	}
}
