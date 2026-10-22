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

//go:build darwin || windows

package e2e

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/checksum"
	"z.gfire.dev/gvx/pkg/tcpip/header"
)

// wireGuardPeer is a wireguard-go device on loopback. Its TUN is an in-memory
// channel. The test reads the decrypted IP packets that the guest sent. It
// also injects the IP packets that the guest must receive.
type wireGuardPeer struct {
	// endpoint is the "ip:port" of the UDP socket of the peer.
	endpoint string
	// tun carries the packets. Inbound holds packets from the guest. A packet
	// that the test writes to Outbound goes to the guest.
	tun *tuntest.ChannelTUN
	dev *device.Device
}

// startWireGuardPeer starts a peer that trusts guestPub and accepts packets
// from guestIP only. The peer closes with the test.
func startWireGuardPeer(t *testing.T, peerPriv, guestPub [32]byte, guestIP netip.Addr) *wireGuardPeer {
	t.Helper()
	ch := tuntest.NewChannelTUN()
	dev := device.NewDevice(ch.TUN(), conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(dev.Close)
	conf := fmt.Sprintf("private_key=%x\nlisten_port=0\npublic_key=%x\nreplace_allowed_ips=true\nallowed_ip=%s\n",
		peerPriv, guestPub, netip.PrefixFrom(guestIP, guestIP.BitLen()))
	if err := dev.IpcSet(conf); err != nil {
		t.Fatalf("configure WireGuard peer: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("bring up WireGuard peer: %v", err)
	}
	state, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("read WireGuard peer state: %v", err)
	}
	for _, line := range strings.Split(state, "\n") {
		if v, ok := strings.CutPrefix(line, "listen_port="); ok {
			if _, err := strconv.ParseUint(v, 10, 16); err != nil {
				t.Fatalf("WireGuard peer listen_port %q: %v", v, err)
			}
			return &wireGuardPeer{endpoint: net.JoinHostPort("127.0.0.1", v), tun: ch, dev: dev}
		}
	}
	t.Fatalf("WireGuard peer reports no listen_port in %q", state)
	return nil
}

// readPacket returns the next decrypted packet from the guest.
func (p *wireGuardPeer) readPacket(t *testing.T, timeout time.Duration) []byte {
	t.Helper()
	select {
	case pkt := <-p.tun.Inbound:
		return pkt
	case <-time.After(timeout):
		t.Fatalf("WireGuard peer received no packet from the guest within %s", timeout)
		return nil
	}
}

// sendPacket delivers an IP packet to the guest through the tunnel.
func (p *wireGuardPeer) sendPacket(t *testing.T, pkt []byte, timeout time.Duration) {
	t.Helper()
	select {
	case p.tun.Outbound <- pkt:
	case <-time.After(timeout):
		t.Fatalf("WireGuard peer could not queue a packet for the guest within %s", timeout)
	}
}

// buildUDPv4Packet returns an IPv4 packet that carries one UDP datagram.
func buildUDPv4Packet(src, dst netip.AddrPort, payload []byte) []byte {
	pkt := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
	udp := header.UDP(pkt[header.IPv4MinimumSize:])
	udp.Encode(&header.UDPFields{
		SrcPort: src.Port(),
		DstPort: dst.Port(),
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})
	copy(udp.Payload(), payload)
	srcAddr, dstAddr := tcpip.AddrFrom4(src.Addr().As4()), tcpip.AddrFrom4(dst.Addr().As4())
	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, srcAddr, dstAddr, uint16(len(udp)))
	udp.SetChecksum(^udp.CalculateChecksum(checksum.Checksum(payload, xsum)))

	ip := header.IPv4(pkt)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(pkt)),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	return pkt
}

// readUDPv4 waits for the next packet from the guest and returns the UDP
// datagram that it carries. It fails the test when the packet is not IPv4 UDP.
func (p *wireGuardPeer) readUDPv4(t *testing.T, timeout time.Duration) (src, dst netip.AddrPort, payload []byte) {
	t.Helper()
	pkt := p.readPacket(t, timeout)
	ip := header.IPv4(pkt)
	if !ip.IsValid(len(pkt)) || ip.TransportProtocol() != header.UDPProtocolNumber {
		t.Fatalf("WireGuard peer received %x, want an IPv4 UDP packet", pkt)
	}
	udp := header.UDP(ip.Payload())
	srcAddr, _ := netip.AddrFromSlice(ip.SourceAddressSlice())
	dstAddr, _ := netip.AddrFromSlice(ip.DestinationAddressSlice())
	return netip.AddrPortFrom(srcAddr, udp.SourcePort()), netip.AddrPortFrom(dstAddr, udp.DestinationPort()), append([]byte(nil), udp.Payload()...)
}
