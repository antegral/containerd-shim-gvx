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
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"
)

const (
	dnsHeaderSize = 12
	dnsTypeA      = 1
	dnsTypeAAAA   = 28
	dnsClassIN    = 1

	dnsFlagQR     = 1 << 15
	dnsFlagAA     = 1 << 10
	dnsFlagTC     = 1 << 9
	dnsFlagRD     = 1 << 8
	dnsFlagRA     = 1 << 7
	dnsRCodeMask  = 0xf
	dnsRCodeNoErr = 0
	dnsRCodeFmt   = 1
	dnsRCodeSrv   = 2
	dnsRCodeNX    = 3
	dnsRCodeRefus = 5

	defaultDNSTTL     = 60
	defaultDNSTimeout = 4 * time.Second

	// dnsUpstreamTimeout is the time that one exchange with one upstream server may take.
	dnsUpstreamTimeout = 2 * time.Second

	// maxDNSMessage is the largest DNS message that a UDP or TCP exchange carries.
	maxDNSMessage = 65535
)

// errNoDNSServers reports that the host has no resolver to forward a query to.
var errNoDNSServers = errors.New("netbackend: no host DNS servers are configured")

type dnsQuestion struct {
	name   string
	qtype  uint16
	qclass uint16
	endOff int
}

func (nf *NATForwarder) serveUDPDNS(ctx context.Context, conn net.Conn) {
	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer stop()

	buf := make([]byte, 4096)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(defaultDNSTimeout))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		resp := nf.handleDNSQuery(ctx, buf[:n])
		if len(resp) > 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(defaultDNSTimeout))
			if _, err := conn.Write(resp); err != nil {
				nf.log.Debug("netbackend: write DNS response to guest", "error", err)
			}
		}
	}
}

func (nf *NATForwarder) serveTCPDNS(ctx context.Context, conn net.Conn) {
	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer stop()
	defer func() {
		_ = conn.Close()
	}()
	var lenBuf [2]byte
	for {
		_ = conn.SetReadDeadline(time.Now().Add(defaultDNSTimeout))
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		msgLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if msgLen == 0 {
			return
		}
		req := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, req); err != nil {
			return
		}
		resp := nf.handleDNSQuery(ctx, req)
		if len(resp) == 0 {
			return
		}
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out[0:2], uint16(len(resp)))
		copy(out[2:], resp)
		_ = conn.SetWriteDeadline(time.Now().Add(defaultDNSTimeout))
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

// handleDNSQuery answers one DNS message. The relay owns a few names and
// resolves A and AAAA queries through the LookupHost hook. It forwards every
// other query to the host DNS servers and answers SERVFAIL when none replies.
func (nf *NATForwarder) handleDNSQuery(ctx context.Context, req []byte) []byte {
	if len(req) < dnsHeaderSize {
		return nil
	}
	txID := binary.BigEndian.Uint16(req[0:2])
	reqFlags := binary.BigEndian.Uint16(req[2:4])
	qdCount := binary.BigEndian.Uint16(req[4:6])
	if qdCount == 0 {
		return buildDNSErrorResponse(txID, reqFlags, nil, dnsRCodeFmt)
	}

	q, err := parseDNSQuestion(req, dnsHeaderSize)
	if err != nil {
		return buildDNSErrorResponse(txID, reqFlags, nil, dnsRCodeFmt)
	}
	rawQuestion := req[dnsHeaderSize:q.endOff]

	if q.qclass == dnsClassIN && (q.qtype == dnsTypeA || q.qtype == dnsTypeAAAA) {
		addrs, found, handled, lookupErr := nf.lookupLocalAddrs(ctx, q.name)
		if lookupErr != nil {
			nf.log.Debug("netbackend: DNS lookup hook failed", "name", q.name, "error", lookupErr)
		}
		if handled {
			if !found {
				return buildDNSErrorResponse(txID, reqFlags, rawQuestion, dnsRCodeNX)
			}
			return buildDNSAddressResponse(txID, reqFlags, rawQuestion, q.qtype, addrs)
		}
	}

	resp, err := nf.forwardRawDNSUpstream(ctx, req)
	if err != nil {
		nf.log.Debug("netbackend: forward DNS query", "name", q.name, "error", err)
		return buildDNSErrorResponse(txID, reqFlags, rawQuestion, dnsRCodeSrv)
	}
	return resp
}

// lookupLocalAddrs resolves the names that the relay answers without an
// upstream server. handled is false when the relay must forward the query.
// found is false for a name that does not exist.
func (nf *NATForwarder) lookupLocalAddrs(ctx context.Context, qname string) (addrs []netip.Addr, found, handled bool, err error) {
	clean := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(qname)), ".")
	switch clean {
	case "localhost", "localhost.localdomain":
		return []netip.Addr{
			netip.MustParseAddr("127.0.0.1"),
			netip.MustParseAddr("::1"),
		}, true, true, nil
	case "host.docker.internal", "gateway.docker.internal":
		if nf.cfg.IsolateLAN {
			return nil, false, true, nil
		}
		return []netip.Addr{netip.MustParseAddr(HostGatewayIPv4)}, true, true, nil
	case "gvx":
		return []netip.Addr{netip.MustParseAddr(DefaultGuestIPv4)}, true, true, nil
	}

	if nf.cfg.LookupHost == nil {
		return nil, false, false, nil
	}
	rctx, cancel := context.WithTimeout(ctx, defaultDNSTimeout)
	defer cancel()

	addrs, err = nf.cfg.LookupHost(rctx, clean)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, false, true, nil
		}
		return nil, false, false, err
	}
	return addrs, true, true, nil
}

// forwardRawDNSUpstream sends the wire query to each host DNS server in turn
// and returns the first usable answer. A server that fails, answers SERVFAIL,
// or answers REFUSED does not stop the search.
func (nf *NATForwarder) forwardRawDNSUpstream(ctx context.Context, req []byte) ([]byte, error) {
	if len(nf.upstreamDNS) == 0 {
		return nil, errNoDNSServers
	}
	var errs []error
	for _, server := range nf.upstreamDNS {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		resp, err := exchangeDNS(ctx, "udp", server, req)
		if err == nil && binary.BigEndian.Uint16(resp[2:4])&dnsFlagTC != 0 {
			resp, err = exchangeDNS(ctx, "tcp", server, req)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("server %s: %w", server, err))
			continue
		}
		switch binary.BigEndian.Uint16(resp[2:4]) & dnsRCodeMask {
		case dnsRCodeSrv, dnsRCodeRefus:
			errs = append(errs, fmt.Errorf("server %s: rcode %d", server, binary.BigEndian.Uint16(resp[2:4])&dnsRCodeMask))
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("netbackend: all upstream DNS servers failed: %w", errors.Join(errs...))
}

// exchangeDNS sends req to server over network ("udp" or "tcp") and returns the
// matching response. The response has a header and the same transaction ID.
func exchangeDNS(ctx context.Context, network, server string, req []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, dnsUpstreamTimeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// The deadline also bounds the read and write calls below.
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	txID := binary.BigEndian.Uint16(req[0:2])
	if network == "tcp" {
		framed := make([]byte, 2+len(req))
		binary.BigEndian.PutUint16(framed[0:2], uint16(len(req)))
		copy(framed[2:], req)
		if _, err := conn.Write(framed); err != nil {
			return nil, err
		}
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return nil, err
		}
		resp := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
		if _, err := io.ReadFull(conn, resp); err != nil {
			return nil, err
		}
		if !validDNSResponse(resp, txID) {
			return nil, errors.New("invalid DNS response")
		}
		return resp, nil
	}

	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	buf := make([]byte, maxDNSMessage)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		// A connected UDP socket accepts datagrams from the server only. The
		// ID check drops late answers to earlier queries on a reused port.
		if validDNSResponse(buf[:n], txID) {
			return buf[:n:n], nil
		}
	}
}

func validDNSResponse(msg []byte, txID uint16) bool {
	return len(msg) >= dnsHeaderSize &&
		binary.BigEndian.Uint16(msg[0:2]) == txID &&
		binary.BigEndian.Uint16(msg[2:4])&dnsFlagQR != 0
}

func parseDNSQuestion(msg []byte, offset int) (dnsQuestion, error) {
	var labels []string
	cur := offset
	for {
		if cur >= len(msg) {
			return dnsQuestion{}, errors.New("truncated DNS label")
		}
		length := int(msg[cur])
		cur++
		if length == 0 {
			break
		}
		if (length & 0xc0) != 0 {
			return dnsQuestion{}, errors.New("compressed label in question not supported")
		}
		if cur+length > len(msg) {
			return dnsQuestion{}, errors.New("DNS label exceeds packet")
		}
		labels = append(labels, string(msg[cur:cur+length]))
		cur += length
	}
	if cur+4 > len(msg) {
		return dnsQuestion{}, errors.New("truncated DNS question fields")
	}
	qtype := binary.BigEndian.Uint16(msg[cur : cur+2])
	qclass := binary.BigEndian.Uint16(msg[cur+2 : cur+4])
	cur += 4
	return dnsQuestion{
		name:   strings.Join(labels, "."),
		qtype:  qtype,
		qclass: qclass,
		endOff: cur,
	}, nil
}

func buildDNSErrorResponse(txID, reqFlags uint16, rawQuestion []byte, rcode uint16) []byte {
	resp := make([]byte, dnsHeaderSize+len(rawQuestion))
	binary.BigEndian.PutUint16(resp[0:2], txID)
	flags := uint16(dnsFlagQR | dnsFlagRA | (reqFlags & dnsFlagRD) | (rcode & 0xf))
	binary.BigEndian.PutUint16(resp[2:4], flags)
	if len(rawQuestion) > 0 {
		binary.BigEndian.PutUint16(resp[4:6], 1)
		copy(resp[dnsHeaderSize:], rawQuestion)
	}
	return resp
}

func buildDNSAddressResponse(txID, reqFlags uint16, rawQuestion []byte, qtype uint16, addrs []netip.Addr) []byte {
	var matched []netip.Addr
	for _, a := range addrs {
		unmapped := a.Unmap()
		if qtype == dnsTypeA && unmapped.Is4() {
			matched = append(matched, unmapped)
		} else if qtype == dnsTypeAAAA && unmapped.Is6() {
			matched = append(matched, unmapped)
		}
	}

	out := make([]byte, dnsHeaderSize, dnsHeaderSize+len(rawQuestion)+len(matched)*28)
	binary.BigEndian.PutUint16(out[0:2], txID)
	flags := uint16(dnsFlagQR | dnsFlagAA | dnsFlagRA | (reqFlags & dnsFlagRD) | dnsRCodeNoErr)
	binary.BigEndian.PutUint16(out[2:4], flags)
	binary.BigEndian.PutUint16(out[4:6], 1) // QDCOUNT
	binary.BigEndian.PutUint16(out[6:8], uint16(len(matched)))
	out = append(out, rawQuestion...)

	for _, addr := range matched {
		// Pointer to QNAME at offset 12 (0xc00c).
		var rrHdr [12]byte
		binary.BigEndian.PutUint16(rrHdr[0:2], 0xc00c)
		binary.BigEndian.PutUint16(rrHdr[2:4], qtype)
		binary.BigEndian.PutUint16(rrHdr[4:6], dnsClassIN)
		binary.BigEndian.PutUint32(rrHdr[6:10], defaultDNSTTL)
		rawIP := addr.AsSlice()
		binary.BigEndian.PutUint16(rrHdr[10:12], uint16(len(rawIP)))
		out = append(out, rrHdr[:]...)
		out = append(out, rawIP...)
	}
	return out
}
