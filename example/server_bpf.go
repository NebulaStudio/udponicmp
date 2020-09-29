// +build bpf

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/czxichen/udponicmp"
	"github.com/xtaci/kcp-go"
)

func server() {
	var err error
	var packet net.PacketConn

	if config.iface != "" {
		packet, err = udponicmp.ListenPacketV4WithBPF(config.iface)
	} else {
		packet, err = udponicmp.ListenPacketV4(true)
	}
	if err != nil {
		panic(err)
	}
	defer packet.Close()

	lis, err := kcp.ServeConn(nil, 10, 3, packet)
	if err != nil {
		panic(err)
	}
	defer lis.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalch := make(chan os.Signal)
	signal.Notify(signalch, os.Kill, os.Interrupt)

	go func() {
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
	}()

	select {
	case <-signalch:
	case <-ctx.Done():
	}
}
