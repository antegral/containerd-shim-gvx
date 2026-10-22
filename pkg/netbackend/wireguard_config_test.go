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
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func b64(k [32]byte) string { return base64.StdEncoding.EncodeToString(k[:]) }

func TestParseWireGuardINI(t *testing.T) {
	priv, pub, psk := newWGPSKStatic(10), newWGPSKStatic(20), newWGPSKStatic(30)
	text := strings.Join([]string{
		"# comment line",
		"[Interface]",
		"PrivateKey = " + b64(priv) + " # inline comment",
		"Address = 10.7.0.2/24, fd00:7::2/64",
		"MTU = 1380",
		"ListenPort = 51999",
		"DNS = 10.7.0.1",
		"",
		"[Peer]",
		"publickey = " + b64(pub),
		"PresharedKey = " + hex.EncodeToString(psk[:]),
		"Endpoint = vpn.example.net:51820",
		"AllowedIPs = 10.7.0.0/24, 192.0.2.5, 2001:db8::/32",
		"PersistentKeepalive = 25",
	}, "\n")
	got, err := ParseWireGuardINI(text)
	if err != nil {
		t.Fatalf("ParseWireGuardINI: %v", err)
	}
	want := WireGuardConfig{
		PrivateKey:    priv,
		PeerPublicKey: pub,
		PresharedKey:  psk,
		PeerEndpoint:  "vpn.example.net:51820",
		GuestIPv4:     netip.MustParsePrefix("10.7.0.2/24"),
		GuestIPv6:     netip.MustParsePrefix("fd00:7::2/64"),
		AllowedIPs: []netip.Prefix{
			netip.MustParsePrefix("10.7.0.0/24"),
			netip.MustParsePrefix("192.0.2.5/32"),
			netip.MustParsePrefix("2001:db8::/32"),
		},
		PersistentKeepalive: 25 * time.Second,
		MTU:                 1380,
		ListenUDPAddr:       ":51999",
	}
	if got.PrivateKey != want.PrivateKey || got.PeerPublicKey != want.PeerPublicKey || got.PresharedKey != want.PresharedKey ||
		got.PeerEndpoint != want.PeerEndpoint || got.GuestIPv4 != want.GuestIPv4 || got.GuestIPv6 != want.GuestIPv6 ||
		!slices.Equal(got.AllowedIPs, want.AllowedIPs) || got.PersistentKeepalive != want.PersistentKeepalive ||
		got.MTU != want.MTU || got.ListenUDPAddr != want.ListenUDPAddr {
		t.Fatalf("parsed config = %+v\nwant %+v", got, want)
	}
}

func TestParseWireGuardINIDefaultsAndBareAddress(t *testing.T) {
	priv, pub := newWGPSKStatic(1), newWGPSKStatic(2)
	text := "[Interface]\nPrivateKey = " + b64(priv) + "\nAddress = 10.7.0.2\n[Peer]\nPublicKey = " + b64(pub) + "\nPersistentKeepalive = off\n"
	got, err := ParseWireGuardINI(text)
	if err != nil {
		t.Fatalf("ParseWireGuardINI: %v", err)
	}
	if got.GuestIPv4 != netip.MustParsePrefix("10.7.0.2/32") {
		t.Fatalf("bare address parsed as %s, want a host prefix 10.7.0.2/32", got.GuestIPv4)
	}
	if got.MTU != DefaultWireGuardMTU || got.ListenUDPAddr != "" || got.PersistentKeepalive != 0 ||
		got.PeerEndpoint != "" || len(got.AllowedIPs) != 0 || got.GuestIPv6.IsValid() {
		t.Fatalf("defaults = %+v", got)
	}

	// Without an Address line the guest keeps the default address after construction.
	got, err = ParseWireGuardINI("[Interface]\nPrivateKey = " + b64(priv) + "\n[Peer]\nPublicKey = " + b64(pub) + "\n")
	if err != nil {
		t.Fatalf("ParseWireGuardINI: %v", err)
	}
	w, err := NewWireGuardEndpoint(got)
	if err != nil {
		t.Fatalf("NewWireGuardEndpoint: %v", err)
	}
	if w.cfg.GuestIPv4 != netip.MustParsePrefix("10.0.2.15/24") || w.cfg.ListenUDPAddr != ":0" {
		t.Fatalf("endpoint defaults = %v %q", w.cfg.GuestIPv4, w.cfg.ListenUDPAddr)
	}
}

func TestParseWireGuardINIRejectsInvalidInput(t *testing.T) {
	priv, pub := b64(newWGPSKStatic(1)), b64(newWGPSKStatic(2))
	iface := "[Interface]\nPrivateKey = " + priv + "\n"
	peer := "[Peer]\nPublicKey = " + pub + "\n"
	tests := []struct {
		name string
		text string
	}{
		{"empty", ""},
		{"no peer", iface},
		{"no interface key", "[Interface]\n" + peer},
		{"peer without key", iface + "[Peer]\nEndpoint = 192.0.2.1:1\n"},
		{"two peers", iface + peer + peer},
		{"peer before interface", peer + iface},
		{"second interface", iface + iface + peer},
		{"unknown section", iface + "[Other]\n" + peer},
		{"key before section", "PrivateKey = " + priv + "\n" + iface + peer},
		{"line without equals", iface + "Address\n" + peer},
		{"bad private key", "[Interface]\nPrivateKey = not-a-key\n" + peer},
		{"short private key", "[Interface]\nPrivateKey = " + base64.StdEncoding.EncodeToString([]byte("short")) + "\n" + peer},
		{"bad peer key", iface + "[Peer]\nPublicKey = zzz\n"},
		{"bad preshared key", iface + peer + "PresharedKey = zzz\n"},
		{"bad address", iface + "Address = 10.0.0.300/24\n" + peer},
		{"two IPv4 addresses", iface + "Address = 10.0.0.2/24, 10.0.1.2/24\n" + peer},
		{"two IPv6 addresses", iface + "Address = fd00::2/64, fd00::3/64\n" + peer},
		{"bad MTU", iface + "MTU = big\n" + peer},
		{"negative MTU", iface + "MTU = -5\n" + peer},
		{"bad listen port", iface + "ListenPort = 70000\n" + peer},
		{"bad allowed ips", iface + peer + "AllowedIPs = 10.0.0.0/8, nonsense\n"},
		{"bad keepalive", iface + peer + "PersistentKeepalive = soon\n"},
		{"keepalive too large", iface + peer + "PersistentKeepalive = 70000\n"},
		{"unknown interface key", iface + "Bogus = 1\n" + peer},
		{"unknown peer key", iface + peer + "Bogus = 1\n"},
		{"interface key in peer section", iface + peer + "MTU = 1400\n"},
		{"PostUp hook", iface + "PostUp = iptables -A FORWARD -j ACCEPT\n" + peer},
		{"PreUp hook", iface + "PreUp = true\n" + peer},
		{"PostDown hook", iface + "PostDown = true\n" + peer},
		{"FwMark", iface + "FwMark = 5\n" + peer},
		{"Table", iface + "Table = off\n" + peer},
		{"SaveConfig", iface + "SaveConfig = true\n" + peer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if cfg, err := ParseWireGuardINI(tt.text); err == nil {
				t.Fatalf("ParseWireGuardINI succeeded with %+v, want an error", cfg)
			}
		})
	}
}

func TestParseWireGuardINIErrorNamesLine(t *testing.T) {
	text := "[Interface]\nPrivateKey = " + b64(newWGPSKStatic(1)) + "\nMTU = big\n"
	_, err := ParseWireGuardINI(text)
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("error = %v, want it to name line 3", err)
	}
}

func TestDecodeWGKey(t *testing.T) {
	key := newWGPSKStatic(5)
	for name, s := range map[string]string{"base64": b64(key), "hex": hex.EncodeToString(key[:])} {
		got, err := decodeWGKey(s)
		if err != nil || got != key {
			t.Fatalf("decodeWGKey(%s) = (%x, %v), want the key", name, got, err)
		}
	}
	for _, s := range []string{"", "AAAA", strings.Repeat("g", 64), b64(key) + "="} {
		if _, err := decodeWGKey(s); err == nil {
			t.Fatalf("decodeWGKey(%q) succeeded, want an error", s)
		}
	}
}
