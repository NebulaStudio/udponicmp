// +build bpf

package udponicmp

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dropbox/goebpf"
	"golang.org/x/net/icmp"
)

// ListenPacketV4WithBPF ListenPacketV4WithBPF
func ListenPacketV4WithBPF(iface string) (net.PacketConn, error) {
	buf, err := hex.DecodeString(ELFBytes)
	if err != nil {
		return nil, err
	}

	bpf := goebpf.NewDefaultEbpfSystem()
	if err := bpf.Load(readerAt(buf)); err != nil {
		return nil, err
	}

	icmpmap := bpf.GetMapByName("icmpmap")
	if icmpmap == nil {
		return nil, fmt.Errorf("ebpf map 'icmpmap' not found")
	}

	perf, err := goebpf.NewPerfEvents(icmpmap)
	if err != nil {
		icmpmap.Close()
		return nil, err
	}

	datachan, err := perf.StartForAllProcessesAndCPUs(4096)
	if err != nil {
		perf.Stop()
		icmpmap.Close()
		return nil, err
	}

	icmpInject := bpf.GetProgramByName("icmp_inject")
	if icmpInject == nil {
		perf.Stop()
		icmpmap.Close()
		return nil, fmt.Errorf("program icmp_inject not found")
	}

	if err := icmpInject.Load(); err != nil {
		icmpInject.Close()
		perf.Stop()
		icmpmap.Close()
		return nil, err
	}

	if err := icmpInject.Attach(iface); err != nil {
		icmpInject.Close()
		perf.Stop()
		icmpmap.Close()
		return nil, err
	}
	p, e := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if e != nil {
		icmpInject.Detach()
		icmpInject.Close()
		perf.Stop()
		icmpmap.Close()
	}
	c := &bpfread{pid: os.Getpid(), datachan: datachan, program: icmpInject, icmpmap: icmpmap, events: perf, icmpPacket: p}
	c.icmpcache = &icmpcache{server: true, echoChan: make(chan *icmpEcho, 1500)}
	go c.read()

	return c, nil
}

type readerAt []byte

// ReadAt ReadAt
func (r readerAt) ReadAt(p []byte, off int64) (int, error) {
	if int64(len(r)) <= off {
		return 0, errors.New("index out off range")
	}
	return copy(p, r[off:]), nil
}

type bpfread struct {
	close      int32
	pid        int
	wmux       sync.Mutex
	icmpmap    goebpf.Map
	datachan   <-chan []byte
	program    goebpf.Program
	events     *goebpf.PerfEvents
	icmpcache  *icmpcache
	icmpPacket *icmp.PacketConn
}

func (b *bpfread) read() {
	for {
		eventData, ok := <-b.datachan
		if !ok {
			return
		}

		if len(eventData) < 8 {
			continue
		}

		eventsize := binary.LittleEndian.Uint64(eventData)
		if eventsize > 34 && eventsize <= headerLen+maxLen {
			b.icmpcache.recv(net.IP(eventData[34:38]), eventData[42:])
		}
	}
}

func (b *bpfread) WriteTo(p []byte, addr net.Addr) (int, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("invalid address")
	}
	echos := newIPv4icmpEcho(true, b.pid, udpAddr.Port, p)

	b.wmux.Lock()
	defer b.wmux.Unlock()

	for _, v := range echos {
		if _, err := b.icmpPacket.WriteTo(v.ICMPData(), &net.IPAddr{IP: udpAddr.IP}); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (b *bpfread) ReadFrom(p []byte) (int, net.Addr, error) {
	return b.icmpcache.readFrom(p)
}

func (b *bpfread) SetDeadline(t time.Time) error { panic("not implement") }

func (b *bpfread) SetReadDeadline(t time.Time) error { panic("not implement") }

func (b *bpfread) SetWriteDeadline(t time.Time) error { return b.icmpPacket.SetWriteDeadline(t) }

func (b *bpfread) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: b.icmpPacket.LocalAddr().(*net.IPAddr).IP, Port: b.pid}
}

func (b *bpfread) Close() error {
	if atomic.CompareAndSwapInt32(&b.close, 0, 1) {
		b.program.Detach()
		b.program.Close()
		b.events.Stop()
		b.icmpmap.Close()
		return b.icmpPacket.Close()
	}
	return nil
}
