package flamingo

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// ConfPOP3 holds configuration for a POP3 capture server.
type ConfPOP3 struct {
	BindPort     uint16
	BindHost     string
	Banner       string
	RecordWriter *RecordWriter
	TLS          bool
	TLSName      string
	TLSCert      string
	TLSKey       string
	shutdown     bool
	listener     net.Listener
	tlsConfig    *tls.Config
	m            sync.Mutex
}

// NewConfPOP3 creates a default configuration for the POP3 capture server.
func NewConfPOP3() *ConfPOP3 {
	return &ConfPOP3{
		BindPort: 110,
		BindHost: "[::]",
		Banner:   "+OK Flamingo POP3 server ready",
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfPOP3) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfPOP3) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	if !c.shutdown {
		c.shutdown = true
		if c.listener != nil {
			c.listener.Close()
		}
	}
}

// SpawnPOP3 creates and starts a new POP3/POP3S capture server.
func SpawnPOP3(c *ConfPOP3) error {
	if c.TLSCert != "" && c.TLSKey != "" {
		kp, err := tls.X509KeyPair([]byte(c.TLSCert), []byte(c.TLSKey))
		if err != nil {
			return fmt.Errorf("failed to load tls cert for pop3: %w", err)
		}
		c.tlsConfig = &tls.Config{
			ServerName:   c.TLSName,
			Certificates: []tls.Certificate{kp},
		}
	}

	addr := fmt.Sprintf("%s:%d", c.BindHost, c.BindPort)
	var listener net.Listener
	var err error

	if c.TLS {
		if c.tlsConfig == nil {
			return fmt.Errorf("tls certificate is required for POP3S listener")
		}
		listener, err = tls.Listen("tcp", addr, c.tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to listen with tls on %s: %w", addr, err)
		}
	} else {
		listener, err = net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %w", addr, err)
		}
	}

	proto := "pop3"
	if c.TLS {
		proto = "pop3s"
	}
	log.Debugf("%s is listening on %s", proto, addr)

	c.listener = listener
	go pop3AcceptLoop(c)
	return nil
}

func pop3AcceptLoop(c *ConfPOP3) {
	for !c.IsShutdown() {
		conn, err := c.listener.Accept()
		if err != nil {
			continue
		}
		go pop3HandleConnection(c, conn)
	}
}

func pop3HandleConnection(c *ConfPOP3, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	banner := c.Banner
	if banner == "" {
		banner = "+OK Flamingo POP3 server ready"
	}
	if !strings.HasPrefix(banner, "+OK") {
		banner = "+OK " + banner
	}
	_, _ = writer.WriteString(banner + "\r\n")
	_ = writer.Flush()

	tlsActive := c.TLS
	var username string

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		cmd := strings.ToUpper(parts[0])
		arg := ""
		if len(parts) > 1 {
			arg = parts[1]
		}

		switch cmd {
		case "CAPA":
			_, _ = writer.WriteString("+OK Capability list follows\r\nUSER\r\nRESP-CODES\r\nAUTH-RESP-CODE\r\nSASL PLAIN LOGIN\r\n")
			if !tlsActive && c.tlsConfig != nil {
				_, _ = writer.WriteString("STLS\r\n")
			}
			_, _ = writer.WriteString(".\r\n")
			_ = writer.Flush()

		case "NOOP":
			_, _ = writer.WriteString("+OK\r\n")
			_ = writer.Flush()

		case "QUIT":
			_, _ = writer.WriteString("+OK Flamingo POP3 server signing off\r\n")
			_ = writer.Flush()
			return

		case "STLS":
			if tlsActive {
				_, _ = writer.WriteString("-ERR TLS already active\r\n")
				_ = writer.Flush()
				continue
			}
			if c.tlsConfig == nil {
				_, _ = writer.WriteString("-ERR STLS not supported\r\n")
				_ = writer.Flush()
				continue
			}

			_, _ = writer.WriteString("+OK Begin TLS negotiation\r\n")
			_ = writer.Flush()

			tlsConn := tls.Server(conn, c.tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				log.Debugf("pop3 STLS handshake failed: %s", err)
				return
			}
			conn = tlsConn
			reader = bufio.NewReader(conn)
			writer = bufio.NewWriter(conn)
			tlsActive = true

		case "USER":
			username = strings.TrimSpace(arg)
			_, _ = writer.WriteString("+OK User accepted, password please\r\n")
			_ = writer.Flush()

		case "PASS":
			password := arg
			if username != "" {
				recordPOP3Credential(c, conn, username, password, "user_pass", tlsActive)
			}
			_, _ = writer.WriteString("-ERR [AUTH] Authentication failed\r\n")
			_ = writer.Flush()
			username = ""

		case "AUTH":
			mech := strings.ToUpper(strings.TrimSpace(arg))
			initial := ""
			if strings.Contains(mech, " ") {
				sub := strings.SplitN(mech, " ", 2)
				mech = sub[0]
				initial = sub[1]
			}

			switch mech {
			case "PLAIN":
				u, p, ok := handleAuthPlain(initial, reader, writer)
				if ok {
					recordPOP3Credential(c, conn, u, p, "auth_plain", tlsActive)
				}
				_, _ = writer.WriteString("-ERR [AUTH] Authentication failed\r\n")
				_ = writer.Flush()

			case "LOGIN":
				u, p, ok := handleAuthLogin(initial, reader, writer)
				if ok {
					recordPOP3Credential(c, conn, u, p, "auth_login", tlsActive)
				}
				_, _ = writer.WriteString("-ERR [AUTH] Authentication failed\r\n")
				_ = writer.Flush()

			default:
				_, _ = writer.WriteString("-ERR Unsupported authentication mechanism\r\n")
				_ = writer.Flush()
			}

		default:
			_, _ = writer.WriteString("-ERR Command unrecognized\r\n")
			_ = writer.Flush()
		}
	}
}

func recordPOP3Credential(c *ConfPOP3, conn net.Conn, username, password, method string, tlsActive bool) {
	if c.RecordWriter == nil {
		return
	}
	pname := "pop3"
	if tlsActive {
		pname = "pop3s"
	}

	c.RecordWriter.Record(
		"credential",
		pname,
		conn.RemoteAddr().String(),
		map[string]string{
			"username": username,
			"password": password,
			"method":   method,
			"_server":  fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
		},
	)
}
