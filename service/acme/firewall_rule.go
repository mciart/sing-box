package acme

import (
	"bytes"
	"net"
	"sort"
)

// firewallAllow is one temporary accept rule. A nil address matches every destination.
type firewallAllow struct {
	port    int
	address net.IP
}

func normalizeFirewallAllows(allows []firewallAllow) []firewallAllow {
	type group struct {
		any bool
		ips map[string]net.IP
	}
	byPort := make(map[int]*group)
	ports := make([]int, 0, len(allows))
	for _, allow := range allows {
		grouped := byPort[allow.port]
		if grouped == nil {
			grouped = &group{ips: make(map[string]net.IP)}
			byPort[allow.port] = grouped
			ports = append(ports, allow.port)
		}
		address := canonicalFirewallIP(allow.address)
		if address == nil {
			grouped.any = true
			continue
		}
		grouped.ips[string(address)] = address
	}
	sort.Ints(ports)
	normalized := make([]firewallAllow, 0, len(allows))
	for _, port := range ports {
		grouped := byPort[port]
		if grouped.any {
			normalized = append(normalized, firewallAllow{port: port})
			continue
		}
		addresses := make([]net.IP, 0, len(grouped.ips))
		for _, address := range grouped.ips {
			addresses = append(addresses, address)
		}
		sort.Slice(addresses, func(i, j int) bool {
			return bytes.Compare(addresses[i], addresses[j]) < 0
		})
		for _, address := range addresses {
			normalized = append(normalized, firewallAllow{port: port, address: address})
		}
	}
	return normalized
}

func canonicalFirewallIP(ip net.IP) net.IP {
	if len(ip) == 0 {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return append(net.IP(nil), v4...)
	}
	v6 := ip.To16()
	if v6 == nil {
		return nil
	}
	return append(net.IP(nil), v6...)
}
