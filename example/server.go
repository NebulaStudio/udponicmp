// +build !bpf

package main

import (
	"fmt"
	"net"
	"time"

	"github.com/czxichen/udponicmp"
	"github.com/xtaci/kcp-go"
)

func server() {
	packet, err := udponicmp.ListenPacketV4(true)
	if err != nil {
		panic(err)
	}
	defer packet.Close()

	lis, err := kcp.ServeConn(nil, 10, 3, packet)
	if err != nil {
		panic(err)
	}
	defer lis.Close()

	fmt.Printf("Listen on: %s\n", lis.Addr().String())
	lis.SetWriteBuffer(4 * 1024 * 1024)
	lis.SetReadBuffer(4 * 1024 * 1024)
	for {
		conn, err := lis.AcceptKCP()
		if err != nil {
			return
		}
		conn.SetWriteDelay(false)
		conn.SetMtu(1350)
		conn.SetWindowSize(1024, 1024)

		go func(conn net.Conn) {
			defer conn.Close()
			buf := make([]byte, 2048)
			for {
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, e := conn.Read(buf)
				if e != nil {
					return
				}
				fmt.Printf("From %s recv %d \n", conn.RemoteAddr().String(), n)
				if _, err := conn.Write(buf[:n]); err != nil {
					return
				}
			}
		}(conn)
	}
}
