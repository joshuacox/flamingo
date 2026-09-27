package flamingo

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	metricsStartTime = time.Now()
	metricsMu        sync.RWMutex
	credentialsCount = make(map[string]*uint64)
	connectionsCount = make(map[string]*uint64)
)

func incMetric(m map[string]*uint64, key string) {
	metricsMu.RLock()
	cnt, exists := m[key]
	metricsMu.RUnlock()

	if exists {
		atomic.AddUint64(cnt, 1)
		return
	}

	metricsMu.Lock()
	cnt, exists = m[key]
	if !exists {
		var n uint64 = 1
		m[key] = &n
	} else {
		atomic.AddUint64(cnt, 1)
	}
	metricsMu.Unlock()
}

// IncrementCredentialsCaptured increments the captured credential metric for a protocol.
func IncrementCredentialsCaptured(proto, method string) {
	key := fmt.Sprintf(`proto="%s",method="%s"`, proto, method)
	incMetric(credentialsCount, key)
}

// IncrementConnections increments connection counter for a protocol.
func IncrementConnections(proto string) {
	key := fmt.Sprintf(`proto="%s"`, proto)
	incMetric(connectionsCount, key)
}

// StartMetricsServer starts a Prometheus-compatible metrics HTTP server.
func StartMetricsServer(port uint16) (*http.Server, error) {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")

		uptime := time.Since(metricsStartTime).Seconds()
		fmt.Fprintf(w, "# HELP flamingo_uptime_seconds Total uptime in seconds\n")
		fmt.Fprintf(w, "# TYPE flamingo_uptime_seconds gauge\n")
		fmt.Fprintf(w, "flamingo_uptime_seconds %.2f\n\n", uptime)

		fmt.Fprintf(w, "# HELP flamingo_credentials_captured_total Total credentials captured\n")
		fmt.Fprintf(w, "# TYPE flamingo_credentials_captured_total counter\n")
		metricsMu.RLock()
		for labels, ptr := range credentialsCount {
			val := atomic.LoadUint64(ptr)
			fmt.Fprintf(w, "flamingo_credentials_captured_total{%s} %d\n", labels, val)
		}

		fmt.Fprintf(w, "\n# HELP flamingo_connections_total Total inbound connections\n")
		fmt.Fprintf(w, "# TYPE flamingo_connections_total counter\n")
		for labels, ptr := range connectionsCount {
			val := atomic.LoadUint64(ptr)
			fmt.Fprintf(w, "flamingo_connections_total{%s} %d\n", labels, val)
		}
		metricsMu.RUnlock()
	})

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	log.Infof("metrics server listening on :%d", port)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("metrics server error: %s", err)
		}
	}()

	return srv, nil
}
