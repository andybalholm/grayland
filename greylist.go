package main

import (
	"sync"
	"time"
)

// A triplet is a combination of client IP, sender, and recipient.
type triplet struct {
	ip   string
	from string
	to   string
}

var (
	greylist = map[triplet]time.Time{}
	ipPassed = map[string]bool{}

	// greylistLock protects both of the maps above.
	greylistLock sync.RWMutex
)

// CheckGreylist checks and updates the greylist. If the combination of
// ip, from, and to was seen before (and recently enough), it returns true and
// the amount of time the message was delayed. If not, it returns false.
func CheckGreylist(ip, from, to string) (passed bool, delay time.Duration) {
	greylistLock.Lock()
	defer greylistLock.Unlock()

	t := triplet{ip, from, to}
	now := time.Now()

	if oldTime, ok := greylist[t]; ok {
		delay = now.Sub(oldTime)
		if delay < 24*time.Hour {
			ipPassed[ip] = true
			return true, delay
		}
	}

	greylist[t] = now
	return false, 0
}

// AlreadyPassed returns whether ip has already passed greylisting.
func AlreadyPassed(ip string) bool {
	greylistLock.RLock()
	defer greylistLock.RUnlock()
	return ipPassed[ip]
}
