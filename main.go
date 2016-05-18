package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"net/textproto"
	"os"
	"strings"
	"time"

	"github.com/andybalholm/milter"
	"golang.org/x/net/publicsuffix"
)

var (
	whitelistFile   = flag.String("whitelist", "", "file of whitelisted domains, IPs, and CIDR ranges")
	whitelist       = map[string]bool{}
	whitelistRanges []*net.IPNet
)

func main() {
	flag.Parse()

	if *whitelistFile != "" {
		if err := loadWhitelist(*whitelistFile); err != nil {
			Log("Error loading whitelist file", "file", *whitelistFile, "error", err)
		}
	}

	listener, err := net.FileListener(os.Stdin)
	if err != nil {
		Fatal("Could not get listener socked from inetd (This program should be started from inetd with the 'wait' option.)", "error", err)
	}

	err = milter.Serve(listener, func() milter.Milter { return &grayMilter{} })
	if err != nil {
		Fatal("Error while running milter", "error", err)
	}
}

func loadWhitelist(filename string) error {
	wl, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer wl.Close()

	s := bufio.NewScanner(wl)
	for s.Scan() {
		line := s.Text()
		if hash := strings.Index(line, "#"); hash != -1 {
			line = line[:hash]
		}
		line = strings.TrimSpace(line)
		if line != "" {
			if _, n, err := net.ParseCIDR(line); err == nil {
				whitelistRanges = append(whitelistRanges, n)
				continue
			}
			whitelist[line] = true
		}
	}
	return s.Err()
}

type grayMilter struct {
	Hostname string
	IP       string
	Sender   string
	Delay    time.Duration
}

var DNSWhitelists = []string{
	"list.dnswl.org",
	"wl.mailspike.net",
	"sa-accredit.habeas.com",
	"iadb.isipp.com",
}

var mailServerPrefixes = []string{
	"mail",
	"smtp",
	"mta",
	"mx",
}

func (g *grayMilter) Connect(hostname string, network string, address string, macros map[string]string) milter.Response {
	switch network {
	case "tcp4", "tcp6":
		g.Hostname = hostname
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			Log("Missing port number in client address", "address", address)
			return milter.Accept
		}
		if host == "127.0.0.1" {
			Log("Connection from localhost")
			return milter.Accept
		}
		g.IP = host

		for _, p := range mailServerPrefixes {
			if strings.Contains(hostname, p) {
				Log("Hostname looks like a mail server", "hostname", hostname, "ip", host)
				return milter.Accept
			}
		}

		if AlreadyPassed(host) {
			Log("Already passed greylist", "hostname", hostname, "ip", host)
			return milter.Accept
		}

		// Check local whitelist.
		if whitelist[host] {
			Log("Whitelisted client IP", "hostname", hostname, "ip", host, "list", *whitelistFile)
			return milter.Accept
		}

		domain := hostname
		for domain != "" {
			if whitelist[domain] {
				Log("Whitelisted client domain", "domain", domain, "hostname", hostname, "ip", host, "list", *whitelistFile)
				return milter.Accept
			}
			dot := strings.Index(domain, ".")
			if dot == -1 {
				break
			}
			domain = domain[dot+1:]
		}

		parsedIP := net.ParseIP(host)
		for _, n := range whitelistRanges {
			if n.Contains(parsedIP) {
				Log("Whitelisted IP range", "hostname", hostname, "ip", host, "range", n)
				return milter.Accept
			}
		}

		if network == "tcp6" {
			// I don't know how to do DNS whitelists with IPv6.
			return milter.Continue
		}

		// Check DNS whitelists.
		parts := strings.Split(host, ".")
		if len(parts) != 4 {
			Log("IP address doesn't have 4 parts", "ip", host)
			return milter.Continue
		}
		parts[0], parts[1], parts[2], parts[3] = parts[3], parts[2], parts[1], parts[0]
		reversed := strings.Join(parts, ".")

		for _, wl := range DNSWhitelists {
			addrs, err := net.LookupHost(reversed + "." + wl)
			if err != nil || len(addrs) == 0 {
				continue
			}
			Log("Whitelisted client IP", "hostname", hostname, "ip", host, "list", wl, "response", addrs[0])
			return milter.Accept
		}

	default:
		Log("Non-TCP connection", "network", network, "address", address)
		return milter.Accept
	}

	return milter.Continue
}

func (g *grayMilter) Helo(name string, macros map[string]string) milter.Response {
	return milter.Continue
}

func (g *grayMilter) From(sender string, macros map[string]string) milter.Response {
	g.Sender = sender
	if user, ok := macros["auth_authen"]; ok {
		Log("Authenticated connection", "user", user, "hostname", g.Hostname, "ip", g.IP, "from", sender)
		return milter.Accept
	}

	// Figure out if the sender's domain sounds legitimate. Legitimate emails
	// usually come from domains with only one label before the public suffix.
	// (e.g. @gmail.com, not @l.to2van.com)
	// We want to do our checks against the MX and A records only for
	// legitimate domains. (If the spammer is spoofing a legitimate domain,
	// those checks will fail.)
	at := strings.Index(sender, "@")
	if at == -1 {
		// Sender address doesn't even have a domain.
		return milter.Continue
	}
	fromDomain := strings.ToLower(sender[at+1:])
	suffix, _ := publicsuffix.PublicSuffix(fromDomain)
	prefix := strings.TrimSuffix(fromDomain, suffix)
	prefix = strings.TrimSuffix(prefix, ".")
	if strings.Contains(prefix, ".") {
		return milter.Continue
	}

	addrs, _ := net.LookupHost(fromDomain)
	for _, ip := range addrs {
		if ip == g.IP {
			Log("IP matches A record", "hostname", g.Hostname, "ip", g.IP, "from", sender, "domain", fromDomain)
			return milter.Accept
		}
	}

	mxs, _ := net.LookupMX(fromDomain)
	for _, mx := range mxs {
		addrs, _ := net.LookupHost(mx.Host)
		for _, ip := range addrs {
			if ip == g.IP {
				Log("IP matches MX record", "hostname", g.Hostname, "ip", g.IP, "from", sender, "domain", fromDomain, "mx", mx.Host)
				return milter.Accept
			}
		}
	}

	return milter.Continue
}

func (g *grayMilter) To(recipient string, macros map[string]string) milter.Response {
	passed, delay := CheckGreylist(g.IP, g.Sender, recipient)
	if passed {
		Log("Passed greylist", "hostname", g.Hostname, "ip", g.IP, "from", g.Sender, "to", recipient, "delay", delay)
		g.Delay = delay
		return milter.Continue
	}

	Log("Greylisted", "hostname", g.Hostname, "ip", g.IP, "from", g.Sender, "to", recipient)
	return milter.CustomResponse{450, "4.2.0 Greylisted"}
}

func (g *grayMilter) Headers(h textproto.MIMEHeader) milter.Response {
	// If the message has already passed through SpamAssassin and been marked OK,
	// log the fact that we delayed a ham message.
	if strings.HasPrefix(h.Get("X-Spam-Status"), "No") && g.Delay != 0 {
		Log("Delayed good message", "hostname", g.Hostname, "ip", g.IP, "from", g.Sender, "to", h.Get("To"), "delay", g.Delay, "subject", h.Get("Subject"))
	}
	return milter.Continue
}

func (g *grayMilter) Body(body []byte, m milter.Modifier) milter.Response {
	if g.Delay != 0 {
		m.AddHeader("X-Greylist", fmt.Sprintf("delayed %v by Grayland", g.Delay))
	}
	return milter.Continue
}
