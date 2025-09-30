package writer

import (
	"fmt"
	"net/netip"

	"go4.org/netipx"
)

// parseIPRange takes IP addresses in string presentation form that represent a
// range and returns an IP range.
func parseIPRange(from, to string) (netipx.IPRange, error) {
	startIP, err := netip.ParseAddr(from)
	if err != nil {
		return netipx.IPRange{}, fmt.Errorf("parsing %s as an IP: %w", from, err)
	}
	endIP, err := netip.ParseAddr(to)
	if err != nil {
		return netipx.IPRange{}, fmt.Errorf("parsing %s as an IP: %w", to, err)
	}
	ipRange := netipx.IPRangeFrom(startIP, endIP)
	if !ipRange.IsValid() {
		return netipx.IPRange{}, fmt.Errorf("%s-%s is an invalid IP range", startIP, endIP)
	}
	return ipRange, nil
}

// parseIPSlice parses a slice of IP address strings and returns a slice of netip.Prefix.
func parseIPSlice(ipAddresses []string) ([]netip.Prefix, error) {
	var addrs []netip.Prefix
	for _, ip := range ipAddresses {
		addr, err := netip.ParsePrefix(ip)
		if err != nil {
			return nil, fmt.Errorf("parsing %s as an IP: %w", ip, err)
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}
