// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netbackend

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/checksum"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

var (
	tunLocalV4  = netip.MustParseAddr("10.9.0.1")
	tunRemoteV4 = netip.MustParseAddr("10.9.0.2")
	tunLocalV6  = netip.MustParseAddr("fd00:9::1")
	tunRemoteV6 = netip.MustParseAddr("fd00:9::2")
)

func newTUNTestStack(t *testing.T) (*channelTUN, *stack.Stack) {
	t.Helper()
	s, ep := newTestStack(t, DefaultWireGuardMTU,
		netip.PrefixFrom(tunLocalV4, 24), netip.PrefixFrom(tunLocalV6, 64))
	tn := newChannelTUN(ep)
	t.Cleanup(func() { _ = tn.Close() })
	return tn, s
}

func buildEchoRequestV4(src, dst netip.Addr, payload []byte) []byte {
	pkt := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize+len(payload))
	icmp := header.ICMPv4(pkt[header.IPv4MinimumSize:])
	icmp.SetType(header.ICMPv4Echo)
	icmp.SetIdent(7)
	icmp.SetSequence(1)
	copy(icmp.Payload(), payload)
	icmp.SetChecksum(^checksum.Checksum(icmp, 0))
	ip := header.IPv4(pkt)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(pkt)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(src.As4()),
		DstAddr:     tcpip.AddrFrom4(dst.As4()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	return pkt
}

func buildEchoRequestV6(src, dst netip.Addr, payload []byte) []byte {
	pkt := make([]byte, header.IPv6MinimumSize+header.ICMPv6EchoMinimumSize+len(payload))
	icmp := header.ICMPv6(pkt[header.IPv6MinimumSize:])
	icmp.SetType(header.ICMPv6EchoRequest)
	icmp.SetIdent(7)
	icmp.SetSequence(1)
	copy(icmp.Payload(), payload)
	srcA, dstA := tcpip.AddrFrom16(src.As16()), tcpip.AddrFrom16(dst.As16())
	icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmp[:header.ICMPv6EchoMinimumSize],
		Src:         srcA,
		Dst:         dstA,
		PayloadCsum: checksum.Checksum(icmp.Payload(), 0),
		PayloadLen:  len(icmp.Payload()),
	}))
	ip := header.IPv6(pkt)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(len(pkt) - header.IPv6MinimumSize),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           srcA,
		DstAddr:           dstA,
	})
	return pkt
}

// readTUN reads one batch and returns copies of the packets.
func readTUN(t *testing.T, tn *channelTUN, batch, offset int) [][]byte {
	t.Helper()
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, offset+2048)
	}
	sizes := make([]int, batch)
	n, err := tn.Read(bufs, sizes, offset)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	out := make([][]byte, n)
	for i := range out {
		out[i] = bytes.Clone(bufs[i][offset : offset+sizes[i]])
	}
	return out
}

func TestChannelTUNMetadata(t *testing.T) {
	tn, _ := newTUNTestStack(t)
	if tn.File() != nil {
		t.Fatalf("File() = %v, want nil because the device has no descriptor", tn.File())
	}
	if mtu, err := tn.MTU(); err != nil || mtu != int(DefaultWireGuardMTU) {
		t.Fatalf("MTU() = (%d, %v), want (%d, nil)", mtu, err, DefaultWireGuardMTU)
	}
	if name, err := tn.Name(); err != nil || name != wgTUNName {
		t.Fatalf("Name() = (%q, %v), want (%q, nil)", name, err, wgTUNName)
	}
	if tn.BatchSize() < 1 {
		t.Fatalf("BatchSize() = %d, want at least 1", tn.BatchSize())
	}
	select {
	case ev, ok := <-tn.Events():
		t.Fatalf("Events() delivered (%v, %v) before Close, want no event", ev, ok)
	default:
	}
}

func TestChannelTUNReadReturnsNetstackPackets(t *testing.T) {
	tn, s := newTUNTestStack(t)
	c, err := gonet.DialUDP(s, nil, &tcpip.FullAddress{Addr: tcpip.AddrFrom4(tunRemoteV4.As4()), Port: 9}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer c.Close()

	// The offset reserves room for the WireGuard transport header. Read must
	// leave the bytes before the offset untouched and place the packet after it.
	const offset = 16
	payload := []byte("outbound-datagram")
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	bufs := [][]byte{bytes.Repeat([]byte{0xAA}, offset+2048)}
	sizes := make([]int, 1)
	n, err := tn.Read(bufs, sizes, offset)
	if err != nil || n != 1 {
		t.Fatalf("Read = (%d, %v), want (1, nil)", n, err)
	}
	if !bytes.Equal(bufs[0][:offset], bytes.Repeat([]byte{0xAA}, offset)) {
		t.Fatalf("Read overwrote the bytes before the offset")
	}
	pkt := bufs[0][offset : offset+sizes[0]]
	ip := header.IPv4(pkt)
	if !ip.IsValid(len(pkt)) || ip.DestinationAddress() != tcpip.AddrFrom4(tunRemoteV4.As4()) ||
		ip.TransportProtocol() != header.UDPProtocolNumber {
		t.Fatalf("Read returned a packet that is not a UDP packet to %s: %x", tunRemoteV4, pkt)
	}
	if got := header.UDP(ip.Payload()).Payload(); !bytes.Equal(got, payload) {
		t.Fatalf("UDP payload = %q, want %q", got, payload)
	}
}

func TestChannelTUNReadBatchesQueuedPackets(t *testing.T) {
	tn, s := newTUNTestStack(t)
	c, err := gonet.DialUDP(s, nil, &tcpip.FullAddress{Addr: tcpip.AddrFrom4(tunRemoteV4.As4()), Port: 9}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer c.Close()
	const total = 5
	for i := range total {
		if _, err := c.Write([]byte{byte(i)}); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	// All five packets are queued, so one Read with room for three returns
	// three and the next Read returns the other two in order.
	first := readTUN(t, tn, 3, 0)
	second := readTUN(t, tn, 3, 0)
	if len(first) != 3 || len(second) != 2 {
		t.Fatalf("batch sizes = (%d, %d), want (3, 2)", len(first), len(second))
	}
	for i, pkt := range append(first, second...) {
		ip := header.IPv4(pkt)
		if got := header.UDP(ip.Payload()).Payload(); !bytes.Equal(got, []byte{byte(i)}) {
			t.Fatalf("packet %d payload = %x, want %x", i, got, []byte{byte(i)})
		}
	}
}

func TestChannelTUNReadDropsPacketThatDoesNotFit(t *testing.T) {
	tn, s := newTUNTestStack(t)
	c, err := gonet.DialUDP(s, nil, &tcpip.FullAddress{Addr: tcpip.AddrFrom4(tunRemoteV4.As4()), Port: 9}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer c.Close()
	if _, err := c.Write(bytes.Repeat([]byte{1}, 600)); err != nil {
		t.Fatalf("Write big: %v", err)
	}
	if _, err := c.Write([]byte("small")); err != nil {
		t.Fatalf("Write small: %v", err)
	}
	bufs := [][]byte{make([]byte, 128)}
	sizes := make([]int, 1)
	n, err := tn.Read(bufs, sizes, 0)
	if err != nil || n != 1 {
		t.Fatalf("Read = (%d, %v), want (1, nil)", n, err)
	}
	if got := header.UDP(header.IPv4(bufs[0][:sizes[0]]).Payload()).Payload(); string(got) != "small" {
		t.Fatalf("Read returned payload %q, want the small packet after the dropped big one", got)
	}
}

func TestChannelTUNWriteInjectsIPv4AndIPv6(t *testing.T) {
	tests := []struct {
		name  string
		req   []byte
		check func(t *testing.T, reply []byte)
	}{
		{
			name: "ipv4",
			req:  buildEchoRequestV4(tunRemoteV4, tunLocalV4, []byte("v4-ping")),
			check: func(t *testing.T, reply []byte) {
				ip := header.IPv4(reply)
				if ip.TransportProtocol() != header.ICMPv4ProtocolNumber ||
					ip.SourceAddress() != tcpip.AddrFrom4(tunLocalV4.As4()) {
					t.Fatalf("IPv4 reply = %x, want an ICMP reply from %s", reply, tunLocalV4)
				}
				icmp := header.ICMPv4(ip.Payload())
				if icmp.Type() != header.ICMPv4EchoReply || !bytes.Equal(icmp.Payload(), []byte("v4-ping")) {
					t.Fatalf("ICMPv4 reply = %x, want an echo reply with the request payload", icmp)
				}
			},
		},
		{
			name: "ipv6",
			req:  buildEchoRequestV6(tunRemoteV6, tunLocalV6, []byte("v6-ping")),
			check: func(t *testing.T, reply []byte) {
				ip := header.IPv6(reply)
				if ip.TransportProtocol() != header.ICMPv6ProtocolNumber ||
					ip.SourceAddress() != tcpip.AddrFrom16(tunLocalV6.As16()) {
					t.Fatalf("IPv6 reply = %x, want an ICMPv6 reply from %s", reply, tunLocalV6)
				}
				icmp := header.ICMPv6(ip.Payload())
				if icmp.Type() != header.ICMPv6EchoReply || !bytes.Equal(icmp.Payload(), []byte("v6-ping")) {
					t.Fatalf("ICMPv6 reply = %x, want an echo reply with the request payload", icmp)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tn, _ := newTUNTestStack(t)
			// A non-zero offset checks that Write ignores the bytes before it.
			const offset = 16
			buf := append(bytes.Repeat([]byte{0xEE}, offset), tt.req...)
			n, err := tn.Write([][]byte{buf}, offset)
			if err != nil || n != 1 {
				t.Fatalf("Write = (%d, %v), want (1, nil)", n, err)
			}
			replies := readTUN(t, tn, 1, 0)
			tt.check(t, replies[0])
		})
	}
}

func TestChannelTUNWriteRejectsInvalidPacketsAndKeepsValidOnes(t *testing.T) {
	tn, _ := newTUNTestStack(t)
	valid := buildEchoRequestV4(tunRemoteV4, tunLocalV4, []byte("ok"))
	bad := [][]byte{
		nil,
		{0x45},
		{0x00, 0x01, 0x02},
		append([]byte{0x75}, make([]byte, 40)...),
		make([]byte, 10),
	}
	for i, b := range bad {
		if n, err := tn.Write([][]byte{b}, 0); n != 0 || !errors.Is(err, errInvalidIPPacket) {
			t.Fatalf("Write(bad packet %d) = (%d, %v), want (0, errInvalidIPPacket)", i, n, err)
		}
	}
	// A bad packet in a batch must not stop delivery of the valid packet.
	n, err := tn.Write([][]byte{bad[2], valid}, 0)
	if n != 1 || !errors.Is(err, errInvalidIPPacket) {
		t.Fatalf("Write(mixed batch) = (%d, %v), want (1, errInvalidIPPacket)", n, err)
	}
	if reply := readTUN(t, tn, 1, 0)[0]; header.IPv4(reply).TransportProtocol() != header.ICMPv4ProtocolNumber {
		t.Fatalf("no echo reply for the valid packet in the mixed batch: %x", reply)
	}
	if n, err := tn.Write([][]byte{valid}, len(valid)+1); err == nil || n != 0 {
		t.Fatalf("Write with offset beyond the buffer = (%d, %v), want an error", n, err)
	}
}

func TestChannelTUNCloseUnblocksReadAndClosesEvents(t *testing.T) {
	tn, _ := newTUNTestStack(t)
	readErr := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		bufs := [][]byte{make([]byte, 2048)}
		_, err := tn.Read(bufs, make([]int, 1), 0)
		readErr <- err
	}()
	<-started
	if err := tn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-readErr:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("blocked Read returned %v, want os.ErrClosed", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("Read stayed blocked after Close")
	}
	if _, ok := <-tn.Events(); ok {
		t.Fatal("Events() channel is open after Close, want closed")
	}
	if err := tn.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := tn.Read([][]byte{make([]byte, 64)}, make([]int, 1), 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Read after Close = %v, want os.ErrClosed", err)
	}
	valid := buildEchoRequestV4(tunRemoteV4, tunLocalV4, nil)
	if _, err := tn.Write([][]byte{valid}, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Write after Close = %v, want os.ErrClosed", err)
	}
}

func TestChannelTUNReadReturnsClosedWhenEndpointCloses(t *testing.T) {
	s, ep := newTestStack(t, DefaultWireGuardMTU, netip.PrefixFrom(tunLocalV4, 24))
	_ = s
	tn := newChannelTUN(ep)
	defer tn.Close()
	ep.Close()
	if _, err := tn.Read([][]byte{make([]byte, 64)}, make([]int, 1), 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Read on a closed endpoint = %v, want os.ErrClosed", err)
	}
}

func TestChannelTUNReadRejectsShortSizes(t *testing.T) {
	tn, _ := newTUNTestStack(t)
	if _, err := tn.Read([][]byte{make([]byte, 64), make([]byte, 64)}, make([]int, 1), 0); err == nil {
		t.Fatal("Read with fewer sizes than buffers succeeded, want an error")
	}
	if _, err := tn.Read(nil, nil, 0); err == nil {
		t.Fatal("Read with no buffers succeeded, want an error")
	}
}
