package flamingo

import (
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// TarpitManager tracks connection frequencies and applies artificial delays to attackers
type TarpitManager struct {
	mu           sync.Mutex
	threshold    int           // Max attempts before tarpitting (0 = disabled)
	window       time.Duration // Time window (e.g. 1 minute)
	delay        time.Duration // Delay per request/response
	attempts     map[string][]time.Time
}

// GlobalTarpit is the singleton tarpit manager
var GlobalTarpit = NewTarpitManager(0, 1*time.Minute, 3*time.Second)

// NewTarpitManager creates a new tarpit manager
func NewTarpitManager(threshold int, window time.Duration, delay time.Duration) *TarpitManager {
	tm := &TarpitManager{
		threshold: threshold,
		window:    window,
		delay:     delay,
		attempts:  make(map[string][]time.Time),
	}
	go tm.cleanupLoop()
	return tm
}

// SetThreshold updates the tarpit threshold
func (tm *TarpitManager) SetThreshold(threshold int) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.threshold = threshold
}

// SetDelay updates the artificial delay duration
func (tm *TarpitManager) SetDelay(delay time.Duration) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.delay = delay
}

// Track registers an attempt from an address and returns true if the IP should be tarpitted
func (tm *TarpitManager) Track(addr string) bool {
	if tm.threshold <= 0 {
		return false
	}

	ip, _, err := net.SplitHostPort(addr)
	if err != nil {
		ip = addr
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-tm.window)

	// Filter out old attempts
	valid := make([]time.Time, 0, len(tm.attempts[ip])+1)
	for _, t := range tm.attempts[ip] {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	valid = append(valid, now)
	tm.attempts[ip] = valid

	if len(valid) > tm.threshold {
		log.Debugf("Tarpit triggered for %s (%d attempts in window)", ip, len(valid))
		return true
	}
	return false
}

// Delay applies the tarpit sleep if the address is currently throttled
func (tm *TarpitManager) Delay(addr string) {
	if tm.Track(addr) {
		time.Sleep(tm.delay)
	}
}

func (tm *TarpitManager) cleanupLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		tm.mu.Lock()
		cutoff := time.Now().Add(-tm.window)
		for ip, timestamps := range tm.attempts {
			validCount := 0
			for _, t := range timestamps {
				if t.After(cutoff) {
					validCount++
				}
			}
			if validCount == 0 {
				delete(tm.attempts, ip)
			}
		}
		tm.mu.Unlock()
	}
}
