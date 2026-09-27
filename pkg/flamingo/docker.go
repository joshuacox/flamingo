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

// ConfDocker contains configuration for Docker Engine API listener
type ConfDocker struct {
	BindHost     string
	BindPort     uint16
	TLS          bool
	TLSCert      string
	TLSKey       string
	TLSName      string
	TLSConfig    *tls.Config
	RecordWriter *RecordWriter
	Version      string
	APIVersion   string
	server       *http.Server
	listener     net.Listener
	mu           sync.Mutex
	shutdown     bool
}

// NewConfDocker creates a new default configuration for Docker API honeypot
func NewConfDocker() *ConfDocker {
	return &ConfDocker{
		BindHost:   "0.0.0.0",
		BindPort:   2375,
		Version:    "24.0.5",
		APIVersion: "1.43",
	}
}

// Shutdown cleanly stops the Docker listener
func (c *ConfDocker) Shutdown() {
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

// SpawnDocker starts the Docker Engine API honeypot
func SpawnDocker(conf *ConfDocker) error {
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
				return fmt.Errorf("failed to load tls cert for docker on %s:%d: %w", conf.BindHost, conf.BindPort, err)
			}
			tlsCfg.Certificates = []tls.Certificate{kp}
			conf.TLSConfig = tlsCfg
		}
		if conf.TLSConfig != nil {
			l = tls.NewListener(l, conf.TLSConfig)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", dockerHandler(conf))

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

func dockerHandler(c *ConfDocker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pname := "docker"
		if c.TLS {
			pname = "dockertls"
		}

		w.Header().Set("Server", fmt.Sprintf("Docker/%s (linux)", c.Version))
		w.Header().Set("API-Version", c.APIVersion)
		w.Header().Set("Docker-Experimental", "false")

		rec := map[string]string{
			"method": r.Method,
			"path":   r.RequestURI,
			"agent":  r.UserAgent(),
		}

		// Check Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			if strings.HasPrefix(strings.ToLower(authHeader), "basic ") {
				rawAuth, err := base64.StdEncoding.DecodeString(strings.TrimSpace(authHeader[6:]))
				if err == nil {
					parts := strings.SplitN(string(rawAuth), ":", 2)
					if len(parts) == 2 {
						rec["username"] = parts[0]
						rec["password"] = parts[1]
					}
				}
			} else if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
				token := strings.TrimSpace(authHeader[7:])
				rec["token"] = token
				rec["password"] = token
			}
		}

		// Normalize path by stripping /vX.XX prefix if present
		path := r.URL.Path
		if strings.HasPrefix(path, "/v1.") {
			slashIdx := strings.Index(path[4:], "/")
			if slashIdx != -1 {
				path = path[4+slashIdx:]
			}
		}

		// Read body for POST / PUT requests (e.g. container creation)
		var bodyBytes []byte
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			bodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, 1024*1024))
			if len(bodyBytes) > 0 {
				rec["payload"] = string(bodyBytes)
				// Try to parse container creation parameters
				var createReq struct {
					Image      string         `json:"Image"`
					Cmd        []string       `json:"Cmd"`
					Entrypoint []string       `json:"Entrypoint"`
					Env        []string       `json:"Env"`
					HostConfig map[string]any `json:"HostConfig"`
				}
				if err := json.Unmarshal(bodyBytes, &createReq); err == nil {
					if createReq.Image != "" {
						rec["image"] = createReq.Image
					}
					if len(createReq.Cmd) > 0 {
						rec["cmd"] = strings.Join(createReq.Cmd, " ")
					}
					if len(createReq.Env) > 0 {
						rec["env"] = strings.Join(createReq.Env, ", ")
					}
				}
			}
		}

		if c.RecordWriter != nil {
			c.RecordWriter.Record("credential", pname, r.RemoteAddr, rec)
		}

		// Handle responses to appear as authentic Docker daemon
		switch {
		case path == "/_ping":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))

		case path == "/version":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			verResp := map[string]interface{}{
				"Platform":   map[string]string{"Name": "Docker Engine - Community"},
				"Components": []map[string]interface{}{{"Name": "Engine", "Version": c.Version, "Details": map[string]string{"ApiVersion": c.APIVersion, "MinAPIVersion": "1.12", "GitCommit": "ced0996", "GoVersion": "go1.20.6", "Os": "linux", "Arch": "amd64"}}},
				"Version":    c.Version,
				"ApiVersion": c.APIVersion,
				"MinAPIVersion": "1.12",
				"GitCommit":  "ced0996",
				"GoVersion":  "go1.20.6",
				"Os":         "linux",
				"Arch":       "amd64",
				"KernelVersion": "5.15.0-89-generic",
				"BuildTime":  "2023-07-24T18:02:11.000000000+00:00",
			}
			_ = json.NewEncoder(w).Encode(verResp)

		case path == "/info":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			infoResp := map[string]interface{}{
				"ID":                "FLAM:INGO:DOCK:ER00:DECE:PTIO:N000:HONEY",
				"Containers":        0,
				"ContainersRunning": 0,
				"ContainersPaused":  0,
				"ContainersStopped": 0,
				"Images":            0,
				"Driver":            "overlay2",
				"MemoryLimit":       true,
				"SwapLimit":         true,
				"KernelVersion":     "5.15.0-89-generic",
				"OperatingSystem":   "Ubuntu 22.04.3 LTS",
				"OSType":            "linux",
				"Architecture":      "x86_64",
				"NCPU":              4,
				"MemTotal":          8342732800,
				"ServerVersion":     c.Version,
			}
			_ = json.NewEncoder(w).Encode(infoResp)

		case path == "/containers/json":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[]\n"))

		case path == "/containers/create":
			// Respond with image not found
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			img := "latest"
			if val, ok := rec["image"]; ok && val != "" {
				img = val
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message": fmt.Sprintf("No such image: %s", img),
			})

		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message": "page not found",
			})
		}

		log.Debugf("Docker honeypot %s request from %s to %s", r.Method, r.RemoteAddr, r.RequestURI)
	}
}
