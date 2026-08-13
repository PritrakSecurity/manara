package api

import (
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// authLimiter throttles login attempts per client IP to slow down brute-force
// attacks against the authentication endpoints.
var authLimiter = newIPRateLimiter(5) // 5 attempts per minute per IP

// visitor tracks the rate limiter for a single client IP.
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// ipRateLimiter is a concurrency-safe map of IP -> *rate.Limiter with
// opportunistic cleanup of stale entries.
type ipRateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	limit    rate.Limit
	burst    int
}

func newIPRateLimiter(perMinute int) *ipRateLimiter {
	return &ipRateLimiter{
		visitors: make(map[string]*visitor),
		limit:    rate.Every(time.Minute / time.Duration(perMinute)),
		burst:    perMinute,
	}
}

// allow reports whether a request from ip is within the rate limit.
func (l *ipRateLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	v, ok := l.visitors[ip]
	if !ok {
		// First request from this IP: allow it and create a limiter.
		l.visitors[ip] = &visitor{limiter: rate.NewLimiter(l.limit, l.burst), lastSeen: time.Now()}
		return true
	}
	v.lastSeen = time.Now()
	return v.limiter.Allow()
}

// cleanup periodically removes visitors that have not been seen recently so the
// map cannot grow without bound.
func (l *ipRateLimiter) cleanup(staleAfter time.Duration) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		l.mu.Lock()
		for ip, v := range l.visitors {
			if time.Since(v.lastSeen) > staleAfter {
				delete(l.visitors, ip)
			}
		}
		l.mu.Unlock()
	}
}

func init() {
	go authLimiter.cleanup(10 * time.Minute)
}

// clientIP extracts the client IP from an http.Request, handling both IPv4 and
// bracketed IPv6 addresses in RemoteAddr.
func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// rateLimitAuth wraps a handler and rejects requests once the per-IP login
// attempt budget is exhausted.
func rateLimitAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authLimiter.allow(clientIP(r)) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "Too many requests",
				"message": "Too many login attempts. Please wait a minute and try again.",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}
