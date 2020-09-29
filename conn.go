package udponicmp

import (
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
)

var _ net.PacketConn = (*icmpconn)(nil)

type icmpconn struct {
	pid        int
	seq        int
	ipv4       bool
	wmux       sync.Mutex
	icmpcache  *icmpcache
	icmpPacket *icmp.PacketConn
}

func (c *icmpconn) read(reader readfrom) {
	buf := make([]byte, 4096)
	if reader == nil {
		reader = c.icmpPacket
	}
	for {
		n, a, e := reader.ReadFrom(buf)
		if e != nil {
			return
		}
		c.icmpcache.recv(a.(*net.IPAddr).IP, buf[:n])
	}
}

func (c *icmpconn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return c.icmpcache.readFrom(p)
}

func (c *icmpconn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("invalid address")
	}
	echos := newIPv4icmpEcho(c.icmpcache.server, c.pid, udpAddr.Port, p)

	c.wmux.Lock()
	defer c.wmux.Unlock()

	for _, v := range echos {
		if _, err := c.icmpPacket.WriteTo(v.ICMPData(), &net.IPAddr{IP: udpAddr.IP}); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (c *icmpconn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: c.icmpPacket.LocalAddr().(*net.IPAddr).IP, Port: c.pid}
}
func (c *icmpconn) Close() error                       { return c.icmpPacket.Close() }
func (c *icmpconn) SetDeadline(t time.Time) error      { panic("not implement") }
func (c *icmpconn) SetReadDeadline(t time.Time) error  { panic("not implement") }
func (c *icmpconn) SetWriteDeadline(t time.Time) error { return c.icmpPacket.SetWriteDeadline(t) }

func newipv4icmpconn(ipv4, server bool, reader readfrom) (net.PacketConn, error) {
	p, e := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if e != nil {
		return nil, e
	}
	conn := &icmpconn{pid: os.Getpid(), ipv4: true, icmpcache: &icmpcache{server: server, echoChan: make(chan *icmpEcho, 1500)}, icmpPacket: p}
	go conn.read(reader)
	return conn, nil
}

// ListenPacketV4 监听端口
func ListenPacketV4(server bool) (net.PacketConn, error) {
	return newipv4icmpconn(server, server, nil)
}

// ListenPacketV6 监听端口
func ListenPacketV6(server bool) (net.PacketConn, error) {
	return nil, errors.New("not implement")
}

type readfrom interface {
	ReadFrom([]byte) (int, net.Addr, error)
	Close() error
}
