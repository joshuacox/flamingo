package flamingo

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/audibleblink/go-ntlm/ntlm"
)

type ConfWinRM struct {
	BindHost     string
	BindPort     uint16
	TLS          bool
	TLSCert      string
	TLSKey       string
	TLSName      string
	TLSConfig    *tls.Config
	AuthMode     string
	RecordWriter *RecordWriter
	server       *http.Server
	listener     net.Listener
}

func NewConfWinRM() *ConfWinRM {
	return &ConfWinRM{
		BindHost: "0.0.0.0",
		BindPort: 5985,
		AuthMode: "ntlm",
	}
}

func (c *ConfWinRM) Shutdown() {
	if c.server != nil {
		_ = c.server.Close()
	}
	if c.listener != nil {
		_ = c.listener.Close()
	}
}

func SpawnWinRM(conf *ConfWinRM) error {
	addr := fmt.Sprintf("%s:%d", conf.BindHost, conf.BindPort)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	conf.listener = l

	if conf.TLS {
		if conf.TLSConfig == nil && conf.TLSCert != "" && conf.TLSKey != "" {
			tlsCfg := &tls.Config{ServerName: conf.TLSName}
			kp, err := tls.X509KeyPair([]byte(conf.TLSCert), []byte(conf.TLSKey))
			if err != nil {
				_ = l.Close()
				return fmt.Errorf("failed to load tls cert for winrms on %s:%d: %w", conf.BindHost, conf.BindPort, err)
			}
			tlsCfg.Certificates = []tls.Certificate{kp}
			conf.TLSConfig = tlsCfg
		}
		if conf.TLSConfig != nil {
			l = tls.NewListener(l, conf.TLSConfig)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", winrmHandler(conf))

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	conf.server = srv

	go func() {
		_ = srv.Serve(l)
	}()

	return nil
}

func winrmHandler(c *ConfWinRM) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Microsoft-HTTPAPI/2.0")

		authHeader := r.Header.Get("Authorization")

		if strings.HasPrefix(strings.ToLower(authHeader), "basic ") {
			rawAuth, err := base64.StdEncoding.DecodeString(strings.TrimSpace(authHeader[6:]))
			if err == nil {
				parts := strings.SplitN(string(rawAuth), ":", 2)
				if len(parts) == 2 {
					pname := "winrm"
					if c.TLS {
						pname = "winrms"
					}
					rec := map[string]string{
						"username":    parts[0],
						"password":    parts[1],
						"method":      "basic",
						"path":        r.RequestURI,
						"soap_action": r.Header.Get("SOAPAction"),
						"agent":       r.UserAgent(),
					}
					if c.RecordWriter != nil {
						c.RecordWriter.Record("credential", pname, r.RemoteAddr, rec)
					}
				}
			}
			w.Header().Set("WWW-Authenticate", "Basic realm=\"WSMAN\"")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if strings.HasPrefix(strings.ToLower(authHeader), "ntlm") {
			ntlmBytes, err := ntlmHeaderBytes(authHeader)
			if err != nil || len(ntlmBytes) < 12 {
				w.Header().Set("WWW-Authenticate", "Negotiate, NTLM")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			msgType := binary.LittleEndian.Uint32(ntlmBytes[8:12])
			if msgType == 1 { // Negotiate (Type 1)
				w.Header().Set("WWW-Authenticate", fmt.Sprintf("NTLM %s", NTLMChallenge))
				w.WriteHeader(http.StatusUnauthorized)
				return
			} else if msgType == 3 { // Authenticate (Type 3)
				hashType := ntlmGetHashType(authHeader)
				authMsg, err := ntlm.ParseAuthenticateMessage(ntlmBytes, hashType)
				if err == nil && authMsg != nil {
					pname := "winrm"
					if c.TLS {
						pname = "winrms"
					}
					rec := map[string]string{
						"username":    authMsg.UserName.String(),
						"domain":      authMsg.DomainName.String(),
						"workstation": authMsg.Workstation.String(),
						"hashcat":     ntlmToHashcat(authMsg, hashType),
						"method":      "NTLMSSP",
						"path":        r.RequestURI,
						"soap_action": r.Header.Get("SOAPAction"),
						"agent":       r.UserAgent(),
					}
					if c.RecordWriter != nil {
						c.RecordWriter.Record("credential", pname, r.RemoteAddr, rec)
					}
				}
				w.Header().Set("WWW-Authenticate", "Negotiate, NTLM")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}

		// Initial unauthenticated probe
		if c.AuthMode == "basic" {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"WSMAN\"")
		} else {
			w.Header().Set("WWW-Authenticate", "Negotiate, NTLM, Basic realm=\"WSMAN\"")
		}
		w.WriteHeader(http.StatusUnauthorized)
	}
}
