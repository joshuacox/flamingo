package flamingo

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// ConfKubelet contains options for the Kubelet API honeypot
type ConfKubelet struct {
	BindHost     string
	BindPort     uint16
	TLS          bool
	TLSCert      string
	TLSKey       string
	TLSName      string
	TLSConfig    *tls.Config
	RecordWriter *RecordWriter
	server       *http.Server
	listener     net.Listener
	mu           sync.Mutex
	shutdown     bool
}

// NewConfKubelet creates a default configuration for Kubelet API listener
func NewConfKubelet() *ConfKubelet {
	return &ConfKubelet{
		BindHost: "0.0.0.0",
		BindPort: 10250,
		TLS:      true,
	}
}

// Shutdown cleanly stops the Kubelet listener
func (c *ConfKubelet) Shutdown() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.shutdown {
		return
	}
	c.shutdown = true
	if c.server != nil {
		_ = c.server.Close()
	}
	if c.listener != nil {
		_ = c.listener.Close()
	}
}

// SpawnKubelet starts the Kubelet API honeypot
func SpawnKubelet(conf *ConfKubelet) error {
	addr := fmt.Sprintf("%s:%d", conf.BindHost, conf.BindPort)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	conf.listener = l
	conf.BindPort = uint16(l.Addr().(*net.TCPAddr).Port)

	if conf.TLS {
		if conf.TLSConfig == nil && conf.TLSCert != "" && conf.TLSKey != "" {
			tlsCfg := &tls.Config{ServerName: conf.TLSName}
			kp, err := tls.X509KeyPair([]byte(conf.TLSCert), []byte(conf.TLSKey))
			if err != nil {
				_ = l.Close()
				return fmt.Errorf("failed to load tls cert for kubelet on %s:%d: %w", conf.BindHost, conf.BindPort, err)
			}
			tlsCfg.Certificates = []tls.Certificate{kp}
			conf.TLSConfig = GlobalTLSRegistry.WrapTLSConfig(tlsCfg)
		}
		if conf.TLSConfig != nil {
			l = tls.NewListener(l, conf.TLSConfig)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", kubeletHandler(conf))

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	conf.server = srv

	go func() {
		_ = srv.Serve(l)
	}()

	return nil
}

func kubeletHandler(c *ConfKubelet) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec := map[string]string{
			"method": r.Method,
			"path":   r.RequestURI,
			"agent":  r.UserAgent(),
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
				token := strings.TrimSpace(authHeader[7:])
				rec["token"] = token
				rec["password"] = token

				// Attempt to decode JWT claims for service account intelligence
				parts := strings.Split(token, ".")
				if len(parts) >= 2 {
					payload, err := base64.RawURLEncoding.DecodeString(parts[1])
					if err == nil {
						var claims map[string]interface{}
						if err := json.Unmarshal(payload, &claims); err == nil {
							if sub, ok := claims["sub"].(string); ok {
								rec["jwt_sub"] = sub
								rec["username"] = sub
							}
							if iss, ok := claims["iss"].(string); ok {
								rec["jwt_iss"] = iss
							}
							if sa, ok := claims["kubernetes.io/serviceaccount/service-account.name"].(string); ok {
								rec["service_account"] = sa
							}
							if ns, ok := claims["kubernetes.io/serviceaccount/namespace"].(string); ok {
								rec["namespace"] = ns
							}
						}
					}
				}
			} else if strings.HasPrefix(strings.ToLower(authHeader), "basic ") {
				rawAuth, err := base64.StdEncoding.DecodeString(strings.TrimSpace(authHeader[6:]))
				if err == nil {
					parts := strings.SplitN(string(rawAuth), ":", 2)
					if len(parts) == 2 {
						rec["username"] = parts[0]
						rec["password"] = parts[1]
					}
				}
			}
		}

		if c.RecordWriter != nil {
			c.RecordWriter.Record("credential", "kubelet", r.RemoteAddr, rec)
		}

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/healthz":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))

		case "/pods", "/runningpods/":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"kind":"PodList","apiVersion":"v1","metadata":{},"items":[]}`))

		default:
			if strings.HasPrefix(r.URL.Path, "/run/") || strings.HasPrefix(r.URL.Path, "/exec/") {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}`))
			} else {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"404 page not found","code":404}`))
			}
		}

		log.Debugf("Kubelet honeypot request from %s to %s", r.RemoteAddr, r.RequestURI)
	}
}

// ConfEtcd contains options for etcd API honeypot
type ConfEtcd struct {
	BindHost     string
	BindPort     uint16
	TLS          bool
	TLSCert      string
	TLSKey       string
	TLSName      string
	TLSConfig    *tls.Config
	RecordWriter *RecordWriter
	server       *http.Server
	listener     net.Listener
	mu           sync.Mutex
	shutdown     bool
}

// NewConfEtcd creates a default configuration for etcd API listener
func NewConfEtcd() *ConfEtcd {
	return &ConfEtcd{
		BindHost: "0.0.0.0",
		BindPort: 2379,
	}
}

// Shutdown cleanly stops the etcd listener
func (c *ConfEtcd) Shutdown() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.shutdown {
		return
	}
	c.shutdown = true
	if c.server != nil {
		_ = c.server.Close()
	}
	if c.listener != nil {
		_ = c.listener.Close()
	}
}

// SpawnEtcd starts the etcd API honeypot
func SpawnEtcd(conf *ConfEtcd) error {
	addr := fmt.Sprintf("%s:%d", conf.BindHost, conf.BindPort)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	conf.listener = l
	conf.BindPort = uint16(l.Addr().(*net.TCPAddr).Port)

	if conf.TLS {
		if conf.TLSConfig == nil && conf.TLSCert != "" && conf.TLSKey != "" {
			tlsCfg := &tls.Config{ServerName: conf.TLSName}
			kp, err := tls.X509KeyPair([]byte(conf.TLSCert), []byte(conf.TLSKey))
			if err != nil {
				_ = l.Close()
				return fmt.Errorf("failed to load tls cert for etcd on %s:%d: %w", conf.BindHost, conf.BindPort, err)
			}
			tlsCfg.Certificates = []tls.Certificate{kp}
			conf.TLSConfig = GlobalTLSRegistry.WrapTLSConfig(tlsCfg)
		}
		if conf.TLSConfig != nil {
			l = tls.NewListener(l, conf.TLSConfig)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", etcdHandler(conf))

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	conf.server = srv

	go func() {
		_ = srv.Serve(l)
	}()

	return nil
}

func etcdHandler(c *ConfEtcd) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec := map[string]string{
			"method": r.Method,
			"path":   r.RequestURI,
			"agent":  r.UserAgent(),
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
				token := strings.TrimSpace(authHeader[7:])
				rec["token"] = token
				rec["password"] = token
			} else if strings.HasPrefix(strings.ToLower(authHeader), "basic ") {
				rawAuth, err := base64.StdEncoding.DecodeString(strings.TrimSpace(authHeader[6:]))
				if err == nil {
					parts := strings.SplitN(string(rawAuth), ":", 2)
					if len(parts) == 2 {
						rec["username"] = parts[0]
						rec["password"] = parts[1]
					}
				}
			}
		}

		// Read body for POST / PUT
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			bodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
			if len(bodyBytes) > 0 {
				rec["payload"] = string(bodyBytes)
				// Check for etcd v3 authenticate request: {"name":"...","password":"..."}
				var authReq struct {
					Name     string `json:"name"`
					Password string `json:"password"`
				}
				if err := json.Unmarshal(bodyBytes, &authReq); err == nil && authReq.Name != "" {
					rec["username"] = authReq.Name
					rec["password"] = authReq.Password
				}
			}
		}

		if c.RecordWriter != nil {
			c.RecordWriter.Record("credential", "etcd", r.RemoteAddr, rec)
		}

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/version":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"etcdserver":"3.5.9","etcdcluster":"3.5.0"}`))

		case "/health":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"health":"true"}`))

		case "/v3/kv/range":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"header":{"cluster_id":14841639079670110514,"member_id":10276657743932906237,"revision":1,"raft_term":1}}`))

		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errorCode":100,"message":"Key not found"}`))
		}

		log.Debugf("etcd honeypot request from %s to %s", r.RemoteAddr, r.RequestURI)
	}
}
