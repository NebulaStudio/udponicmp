package udponicmp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"

	"golang.org/x/net/ipv4"
)

const maxLen = 1450
const headerLen = 8 + 8 // icmp + header
var zeroicmp = []byte{0, 0, 0, 0, 0, 0, 0, 0}
var icmp2udp = []byte("icmp2udp")
var icmpbodyPool = new(sync.Pool)

func createICMPEcho(data []byte) *icmpEcho {
	dataLen := len(data)
	if dataLen > maxLen {
		return nil
	}
	i, o := icmpbodyPool.Get().(*icmpEcho)
	if !o {
		i = &icmpEcho{data: make([]byte, headerLen+maxLen)}
		copy(i.data[8:headerLen], icmp2udp)
	} else {
		copy(i.data[0:8], zeroicmp)
	}
	copy(i.data[headerLen:], data)
	i.dlen = headerLen + dataLen
	return i
}

func deleteICMPEcho(i *icmpEcho) {
	i.dlen = 0
	icmpbodyPool.Put(i)
}

type icmpEcho struct {
	addr net.Addr
	dlen int
	data []byte
}

func (i *icmpEcho) ID() uint16 {
	return binary.BigEndian.Uint16(i.data[4:6])
}

func (i *icmpEcho) Seq() uint16 {
	return binary.BigEndian.Uint16(i.data[6:8])
}

func (i *icmpEcho) Data() []byte {
	return i.data[headerLen:i.dlen]
}

func (i *icmpEcho) ICMPData() []byte {
	return i.data[:i.dlen]
}

func (i *icmpEcho) DataLen() int {
	return i.dlen - headerLen
}

func (i *icmpEcho) ICMPDataLen() int {
	return i.dlen
}

func (i *icmpEcho) Copy(offset int, data []byte) int {
	return copy(data, i.data[headerLen+offset:i.dlen])
}

func newIPv4icmpEchoFromData(data []byte) (*icmpEcho, error) {
	dataLen := len(data)
	if dataLen <= headerLen || dataLen > maxLen+headerLen {
		return nil, errors.New("invalid data length")
	}
	icmpecho := createICMPEcho(data[headerLen:])
	copy(icmpecho.data[0:8], data[0:8])
	return icmpecho, nil
}

func newIPv4icmpEcho(server bool, id, port int, data []byte) []*icmpEcho {
	dataLen := len(data)
	num := dataLen / maxLen
	fix := dataLen % maxLen

	if server {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(port))
		id = int(binary.BigEndian.Uint16(buf[0:2]))
		port = int(binary.BigEndian.Uint16(buf[2:4]))
	}
	if fix > 0 {
		num++
	} else {
		fix = maxLen
	}

	bodys := make([]*icmpEcho, num)
	if num == 0 {
		return bodys
	}

	icmpType := byte(ipv4.ICMPTypeEcho)
	if server {
		icmpType = byte(ipv4.ICMPTypeEchoReply)
	}

	idx := 0
	for v := 0; v < num-1; v++ {
		icmpecho := createICMPEcho(data[idx : idx+maxLen])
		icmpecho.data[0] = icmpType
		icmpecho.data[4], icmpecho.data[5] = byte(id>>8), byte(id)
		icmpecho.data[6], icmpecho.data[7] = byte(port>>8), byte(port)
		sum := checksum(icmpecho.ICMPData())
		icmpecho.data[2] ^= byte(sum)
		icmpecho.data[3] ^= byte(sum >> 8)
		bodys[v] = icmpecho
		idx += maxLen
	}
	icmpecho := createICMPEcho(data[idx : idx+fix])
	icmpecho.data[0] = icmpType
	icmpecho.data[4], icmpecho.data[5] = byte(id>>8), byte(id)
	icmpecho.data[6], icmpecho.data[7] = byte(port>>8), byte(port)
	sum := checksum(icmpecho.ICMPData())
	icmpecho.data[2] ^= byte(sum)
	icmpecho.data[3] ^= byte(sum >> 8)
	bodys[num-1] = icmpecho

	return bodys
}

func newIPv6icmpEcho(data []byte) []*icmpEcho {
	return nil
}

type icmpcache struct {
	current  int32
	seq      int
	idx      int
	dataLen  int
	server   bool
	echo     *icmpEcho
	echoChan chan *icmpEcho
}

func (e *icmpcache) recv(ip net.IP, data []byte) error {
	echo, err := newIPv4icmpEchoFromData(data)
	if err != nil {
		return err
	}
	if e.server {
		echo.addr = newUDPAddress(ip, echo.ID(), echo.Seq())
	} else {
		echo.addr = &net.UDPAddr{IP: ip, Port: int(echo.Seq())}
	}
	select {
	case e.echoChan <- echo:
	default:
	}
	return nil
}

func (e *icmpcache) readFrom(p []byte) (n int, addr net.Addr, err error) {
	plen := len(p)
	if plen == 0 {
		return 0, &net.UDPAddr{}, nil
	}
	for {
		if e.echo != nil {
			n = e.echo.Copy(e.idx, p)
			e.idx += n
			addr = e.echo.addr
			if e.idx >= e.dataLen {
				e.idx = 0
				e.dataLen = 0
				deleteICMPEcho(e.echo)
				e.echo = nil
			}
			return n, addr, nil
		}
		e.echo = <-e.echoChan
		if e.echo == nil {
			return n, addr, errors.New("icmp echo chan is closed")
		}
		e.dataLen = e.echo.DataLen()
	}
}

func newUDPAddress(ip net.IP, sport, dport uint16) *net.UDPAddr {
	var port = make([]byte, 4)
	binary.BigEndian.PutUint16(port[0:2], sport)
	binary.BigEndian.PutUint16(port[2:4], dport)
	return &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint32(port))}
}

type address struct {
	ip    net.IP
	sport uint16
	dport uint16
}

func (a *address) Network() string { return "udp" }

func (a *address) String() string { return fmt.Sprintf("%s:%d:%d", a.ip.String(), a.sport, a.dport) }

func checksum(b []byte) uint16 {
	csumcv := len(b) - 1 // checksum coverage
	s := uint32(0)
	for i := 0; i < csumcv; i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	if csumcv&1 == 0 {
		s += uint32(b[csumcv])
	}
	s = s>>16 + s&0xffff
	s = s + s>>16
	return ^uint16(s)
}
