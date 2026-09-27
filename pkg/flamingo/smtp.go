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

// ConfSMTP holds configuration for an SMTP capture server.
type ConfSMTP struct {
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

// NewConfSMTP creates a default configuration for the SMTP capture server.
func NewConfSMTP() *ConfSMTP {
	return &ConfSMTP{
		BindPort: 25,
		BindHost: "[::]",
		Banner:   "220 Flamingo ESMTP Service ready",
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfSMTP) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfSMTP) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	if !c.shutdown {
		c.shutdown = true
		if c.listener != nil {
			c.listener.Close()
		}
	}
}

// SpawnSMTP creates and starts a new SMTP/SMTPS capture server.
func SpawnSMTP(c *ConfSMTP) error {
	if c.TLSCert != "" && c.TLSKey != "" {
		kp, err := tls.X509KeyPair([]byte(c.TLSCert), []byte(c.TLSKey))
		if err != nil {
			return fmt.Errorf("failed to load tls cert for smtp: %w", err)
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
			return fmt.Errorf("tls certificate is required for SMTPS listener")
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

	proto := "smtp"
	if c.TLS {
		proto = "smtps"
	}
	log.Debugf("%s is listening on %s", proto, addr)

	c.listener = listener
	go smtpAcceptLoop(c)
	return nil
}

func smtpAcceptLoop(c *ConfSMTP) {
	for !c.IsShutdown() {
		conn, err := c.listener.Accept()
		if err != nil {
			continue
		}
		go smtpHandleConnection(c, conn)
	}
}

func smtpHandleConnection(c *ConfSMTP, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	banner := c.Banner
	if banner == "" {
		banner = "220 Flamingo ESMTP Service ready"
	}
	if !strings.HasPrefix(banner, "220") {
		banner = "220 " + banner
	}
	_, _ = writer.WriteString(banner + "\r\n")
	_ = writer.Flush()

	tlsActive := c.TLS
	var mailFrom, rcptTo string

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
		case "HELO":
			_, _ = writer.WriteString("250 Flamingo Hello\r\n")
			_ = writer.Flush()

		case "EHLO":
			res := "250-Flamingo Hello\r\n250-AUTH LOGIN PLAIN\r\n250-8BITMIME\r\n250-ENHANCEDSTATUSCODES\r\n"
			if !tlsActive && c.tlsConfig != nil {
				res += "250-STARTTLS\r\n"
			}
			res += "250 OK\r\n"
			_, _ = writer.WriteString(res)
			_ = writer.Flush()

		case "STARTTLS":
			if tlsActive {
				_, _ = writer.WriteString("503 5.5.1 TLS already active\r\n")
				_ = writer.Flush()
				continue
			}
			if c.tlsConfig == nil {
				_, _ = writer.WriteString("454 4.7.0 TLS not available\r\n")
				_ = writer.Flush()
				continue
			}

			_, _ = writer.WriteString("220 2.0.0 Ready to start TLS\r\n")
			_ = writer.Flush()

			tlsConn := tls.Server(conn, c.tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				log.Debugf("smtp STARTTLS handshake failed: %s", err)
				return
			}
			conn = tlsConn
			reader = bufio.NewReader(conn)
			writer = bufio.NewWriter(conn)
			tlsActive = true

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
					recordSMTPCredential(c, conn, u, p, "auth_plain", mailFrom, rcptTo, tlsActive)
				}
				_, _ = writer.WriteString("535 5.7.8 Authentication credentials invalid\r\n")
				_ = writer.Flush()

			case "LOGIN":
				u, p, ok := handleAuthLogin(initial, reader, writer)
				if ok {
					recordSMTPCredential(c, conn, u, p, "auth_login", mailFrom, rcptTo, tlsActive)
				}
				_, _ = writer.WriteString("535 5.7.8 Authentication credentials invalid\r\n")
				_ = writer.Flush()

			default:
				_, _ = writer.WriteString("504 5.7.4 Unrecognized authentication type\r\n")
				_ = writer.Flush()
			}

		case "MAIL":
			// MAIL FROM:<...>
			mailFrom = arg
			_, _ = writer.WriteString("250 2.1.0 Sender OK\r\n")
			_ = writer.Flush()

		case "RCPT":
			// RCPT TO:<...>
			rcptTo = arg
			_, _ = writer.WriteString("250 2.1.5 Recipient OK\r\n")
			_ = writer.Flush()

		case "DATA":
			_, _ = writer.WriteString("354 Start mail input; end with <CRLF>.<CRLF>\r\n")
			_ = writer.Flush()
			for {
				dataLine, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(dataLine, "\r\n") == "." {
					break
				}
			}
			_, _ = writer.WriteString("250 2.0.0 Message accepted for delivery\r\n")
			_ = writer.Flush()

		case "RSET":
			mailFrom = ""
			rcptTo = ""
			_, _ = writer.WriteString("250 2.0.0 OK\r\n")
			_ = writer.Flush()

		case "NOOP":
			_, _ = writer.WriteString("250 2.0.0 OK\r\n")
			_ = writer.Flush()

		case "QUIT":
			_, _ = writer.WriteString("221 2.0.0 Flamingo Service closing transmission channel\r\n")
			_ = writer.Flush()
			return

		default:
			_, _ = writer.WriteString("500 5.5.2 Syntax error, command unrecognized\r\n")
			_ = writer.Flush()
		}
	}
}

func recordSMTPCredential(c *ConfSMTP, conn net.Conn, username, password, method, mailFrom, rcptTo string, tlsActive bool) {
	if c.RecordWriter == nil {
		return
	}
	pname := "smtp"
	if tlsActive {
		pname = "smtps"
	}

	params := map[string]string{
		"username": username,
		"password": password,
		"method":   method,
		"_server":  fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
	}
	if mailFrom != "" {
		params["mail_from"] = mailFrom
	}
	if rcptTo != "" {
		params["rcpt_to"] = rcptTo
	}

	c.RecordWriter.Record("credential", pname, conn.RemoteAddr().String(), params)
}
