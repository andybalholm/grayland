package main

import (
	"net"
	"strings"
)

// SPFValidated returns whether ip is a valid sender according to domain's SPF
// record. No more than maxDepth invocations can run recursively (to
// to prevent infinite loops). Only a small subset of the SPF spec is
// implemented.
func SPFValidated(ip, domain string, maxDepth int) bool {
	if maxDepth < 1 {
		return false
	}

	txts, err := net.LookupTXT(domain)
	if err != nil {
		return false
	}

	var spf string
	for _, s := range txts {
		if strings.HasPrefix(s, "v=spf1 ") {
			spf = s
			break
		}
	}
	if spf == "" {
		return false
	}

	parsedIP := net.ParseIP(ip)

	for _, w := range strings.Fields(spf)[1:] {
		w = strings.TrimPrefix(w, "+")

		switch {
		case w == "a":
			addrs, _ := net.LookupHost(domain)
			for _, a := range addrs {
				if a == ip {
					return true
				}
			}

		case strings.HasPrefix(w, "a:"):
			addrs, _ := net.LookupHost(strings.TrimPrefix(w, "a:"))
			for _, a := range addrs {
				if a == ip {
					return true
				}
			}

		case w == "mx":
			mxs, _ := net.LookupMX(domain)
			for _, mx := range mxs {
				addrs, _ := net.LookupHost(mx.Host)
				for _, a := range addrs {
					if a == ip {
						return true
					}
				}
			}

		case strings.HasPrefix(w, "mx:"):
			mxs, _ := net.LookupMX(strings.TrimPrefix(w, "mx:"))
			for _, mx := range mxs {
				addrs, _ := net.LookupHost(mx.Host)
				for _, a := range addrs {
					if a == ip {
						return true
					}
				}
			}

		case strings.HasPrefix(w, "ip4:") || strings.HasPrefix(w, "ip6:"):
			addr := w[len("ip4:"):]
			if strings.Contains(addr, "/") {
				_, n, err := net.ParseCIDR(addr)
				if err == nil && n.Contains(parsedIP) {
					return true
				}
			} else {
				if addr == ip {
					return true
				}
			}

		case strings.HasPrefix(w, "include:"):
			if SPFValidated(ip, strings.TrimPrefix(w, "include:"), maxDepth-1) {
				return true
			}

		case strings.HasPrefix(w, "redirect="):
			return SPFValidated(ip, strings.TrimPrefix(w, "redirect="), maxDepth-1)
		}
	}

	return false
}
