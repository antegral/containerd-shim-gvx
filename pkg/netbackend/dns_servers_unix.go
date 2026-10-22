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

//go:build !windows

package netbackend

import (
	"net"
	"net/netip"
	"os"
	"strings"
)

// resolvConfPath is the macOS and Unix resolver configuration file.
const resolvConfPath = "/etc/resolv.conf"

// discoverHostDNSServers returns the "host:port" address of each nameserver
// in /etc/resolv.conf. It runs before hostlockdown.Apply, because lockdown
// denies reads outside the workspace. It returns nil when the file is missing
// or lists no valid nameserver, so the relay then answers SERVFAIL.
func discoverHostDNSServers() []string {
	raw, err := os.ReadFile(resolvConfPath)
	if err != nil {
		return nil
	}
	return parseResolvConf(string(raw))
}

// parseResolvConf extracts the nameserver addresses of a resolv.conf file.
func parseResolvConf(text string) []string {
	var servers []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "nameserver") {
			continue
		}
		addr, err := netip.ParseAddr(fields[1])
		if err != nil || addr.IsUnspecified() {
			continue
		}
		servers = append(servers, net.JoinHostPort(addr.String(), "53"))
	}
	return servers
}
