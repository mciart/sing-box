//go:build with_acme

package acme

import (
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// listenGate serializes HTTP-01 listeners for one ACME issuer. certmagic reads
// ListenHost when it creates the challenge socket, and one issuer can obtain
// more than one address at the same time.
type listenGate struct {
	mu     sync.Mutex
	owner  atomic.Int64
	depth  int
	active bool
}

func (g *listenGate) Lock() {
	gid := currentGoroutineID()
	if g.owner.Load() == gid {
		g.depth++
		return
	}
	g.mu.Lock()
	g.owner.Store(gid)
	g.depth = 1
}

func (g *listenGate) Unlock() {
	if g.owner.Load() != currentGoroutineID() {
		return
	}
	g.depth = 0
	g.owner.Store(0)
	g.mu.Unlock()
}

func currentGoroutineID() int64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	fields := strings.Fields(string(buf[:n]))
	if len(fields) < 2 {
		return 0
	}
	id, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return id
}

func challengeListenHost(identifier string) string {
	ip := net.ParseIP(identifier)
	if ip == nil {
		return ""
	}
	return ip.String()
}
