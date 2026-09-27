package flamingo

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// ConfIMAP holds configuration for an IMAP capture server.
type ConfIMAP struct {
	BindPort     uint16
	BindHost     string
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

// NewConfIMAP creates a default configuration for the IMAP capture server.
func NewConfIMAP() *ConfIMAP {
	return &ConfIMAP{
		BindPort: 143,
		BindHost: "[::]",
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfIMAP) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfIMAP) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	if !c.shutdown {
		c.shutdown = true
		if c.listener != nil {
			c.listener.Close()
		}
	}
}

// SpawnIMAP creates and starts a new IMAP/IMAPS capture server.
func SpawnIMAP(c *ConfIMAP) error {
	if c.TLSCert != "" && c.TLSKey != "" {
		kp, err := tls.X509KeyPair([]byte(c.TLSCert), []byte(c.TLSKey))
		if err != nil {
			return fmt.Errorf("failed to load tls cert for imap: %w", err)
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
			return fmt.Errorf("tls certificate is required for IMAPS listener")
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

	proto := "imap"
	if c.TLS {
		proto = "imaps"
	}
	log.Debugf("%s is listening on %s", proto, addr)

	c.listener = listener
	go imapAcceptLoop(c)
	return nil
}

func imapAcceptLoop(c *ConfIMAP) {
	for !c.IsShutdown() {
		conn, err := c.listener.Accept()
		if err != nil {
			continue
		}
		go imapHandleConnection(c, conn)
	}
}

func imapHandleConnection(c *ConfIMAP, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Send initial greeting
	_, _ = writer.WriteString("* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=LOGIN STARTTLS] Flamingo IMAP4rev1 ready\r\n")
	_ = writer.Flush()

	tlsActive := c.TLS

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 2 {
			_, _ = writer.WriteString("* BAD Invalid command format\r\n")
			_ = writer.Flush()
			continue
		}

		tag := parts[0]
		cmd := strings.ToUpper(parts[1])
		rest := ""
		if len(parts) > 2 {
			rest = parts[2]
		}

		switch cmd {
		case "CAPABILITY":
			caps := "IMAP4rev1 AUTH=PLAIN AUTH=LOGIN"
			if !tlsActive && c.tlsConfig != nil {
				caps += " STARTTLS"
			}
			_, _ = writer.WriteString(fmt.Sprintf("* CAPABILITY %s\r\n%s OK CAPABILITY completed\r\n", caps, tag))
			_ = writer.Flush()

		case "NOOP":
			_, _ = writer.WriteString(fmt.Sprintf("%s OK NOOP completed\r\n", tag))
			_ = writer.Flush()

		case "LOGOUT":
			_, _ = writer.WriteString(fmt.Sprintf("* BYE Flamingo IMAP4rev1 server logging out\r\n%s OK LOGOUT completed\r\n", tag))
			_ = writer.Flush()
			return

		case "STARTTLS":
			if tlsActive {
				_, _ = writer.WriteString(fmt.Sprintf("%s BAD TLS already active\r\n", tag))
				_ = writer.Flush()
				continue
			}
			if c.tlsConfig == nil {
				_, _ = writer.WriteString(fmt.Sprintf("%s NO STARTTLS not available\r\n", tag))
				_ = writer.Flush()
				continue
			}

			_, _ = writer.WriteString(fmt.Sprintf("%s OK Begin TLS negotiation now\r\n", tag))
			_ = writer.Flush()

			tlsConn := tls.Server(conn, c.tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				log.Debugf("imap STARTTLS handshake failed: %s", err)
				return
			}
			conn = tlsConn
			reader = bufio.NewReader(conn)
			writer = bufio.NewWriter(conn)
			tlsActive = true

		case "LOGIN":
			u, p, ok := parseImapLoginArgs(rest, reader, writer)
			if !ok {
				_, _ = writer.WriteString(fmt.Sprintf("%s BAD Missing or invalid arguments to LOGIN\r\n", tag))
				_ = writer.Flush()
				continue
			}

			recordImapCredential(c, conn, u, p, "login", tlsActive)
			_, _ = writer.WriteString(fmt.Sprintf("%s NO [AUTHENTICATIONFAILED] Invalid credentials\r\n", tag))
			_ = writer.Flush()

		case "AUTHENTICATE":
			authMech := strings.ToUpper(strings.TrimSpace(rest))
			authArgs := ""
			if strings.Contains(authMech, " ") {
				subparts := strings.SplitN(authMech, " ", 2)
				authMech = subparts[0]
				authArgs = subparts[1]
			}

			switch authMech {
			case "PLAIN":
				u, p, ok := handleAuthPlain(authArgs, reader, writer)
				if ok {
					recordImapCredential(c, conn, u, p, "auth_plain", tlsActive)
				}
				_, _ = writer.WriteString(fmt.Sprintf("%s NO [AUTHENTICATIONFAILED] Authentication failed\r\n", tag))
				_ = writer.Flush()

			case "LOGIN":
				u, p, ok := handleAuthLogin(authArgs, reader, writer)
				if ok {
					recordImapCredential(c, conn, u, p, "auth_login", tlsActive)
				}
				_, _ = writer.WriteString(fmt.Sprintf("%s NO [AUTHENTICATIONFAILED] Authentication failed\r\n", tag))
				_ = writer.Flush()

			default:
				_, _ = writer.WriteString(fmt.Sprintf("%s NO Unsupported authentication mechanism\r\n", tag))
				_ = writer.Flush()
			}

		default:
			_, _ = writer.WriteString(fmt.Sprintf("%s BAD Unknown or unsupported command\r\n", tag))
			_ = writer.Flush()
		}
	}
}

func parseImapLoginArgs(rest string, reader *bufio.Reader, writer *bufio.Writer) (string, string, bool) {
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", "", false
	}

	u, rest, ok := parseNextImapToken(rest, reader, writer)
	if !ok {
		return "", "", false
	}

	rest = strings.TrimSpace(rest)
	p, _, ok := parseNextImapToken(rest, reader, writer)
	if !ok {
		return "", "", false
	}

	return u, p, true
}

func parseNextImapToken(s string, reader *bufio.Reader, writer *bufio.Writer) (string, string, bool) {
	s = strings.TrimLeft(s, " ")
	if s == "" {
		return "", "", false
	}

	// Double quoted string: "..."
	if strings.HasPrefix(s, "\"") {
		idx := 1
		var token strings.Builder
		for idx < len(s) {
			if s[idx] == '\\' && idx+1 < len(s) {
				token.WriteByte(s[idx+1])
				idx += 2
				continue
			}
			if s[idx] == '"' {
				return token.String(), s[idx+1:], true
			}
			token.WriteByte(s[idx])
			idx++
		}
		return "", "", false
	}

	// Literal string: {len}
	if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
		numStr := s[1 : len(s)-1]
		n, err := strconv.Atoi(numStr)
		if err != nil || n < 0 || n > 65536 {
			return "", "", false
		}
		// Send continuation prompt
		_, _ = writer.WriteString("+ Ready for literal data\r\n")
		_ = writer.Flush()

		buf := make([]byte, n)
		_, err = io.ReadFull(reader, buf)
		if err != nil {
			return "", "", false
		}
		return string(buf), "", true
	}

	// Normal space-delimited atom
	parts := strings.SplitN(s, " ", 2)
	token := parts[0]
	remainder := ""
	if len(parts) > 1 {
		remainder = parts[1]
	}
	return token, remainder, true
}

func handleAuthPlain(initial string, reader *bufio.Reader, writer *bufio.Writer) (string, string, bool) {
	data := strings.TrimSpace(initial)
	if data == "" {
		// Send continuation request
		_, _ = writer.WriteString("+ \r\n")
		_ = writer.Flush()

		line, err := reader.ReadString('\n')
		if err != nil {
			return "", "", false
		}
		data = strings.TrimRight(line, "\r\n")
	}

	if data == "*" {
		return "", "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", "", false
	}

	// Format is [authzid]\0authcid\0passwd
	parts := strings.Split(string(decoded), "\x00")
	if len(parts) == 3 {
		return parts[1], parts[2], true
	} else if len(parts) == 2 {
		return parts[0], parts[1], true
	}

	return "", "", false
}

func handleAuthLogin(initial string, reader *bufio.Reader, writer *bufio.Writer) (string, string, bool) {
	uStr := strings.TrimSpace(initial)
	if uStr == "" {
		// Challenge for Username (base64 of "Username:")
		_, _ = writer.WriteString("+ VXNlcm5hbWU6\r\n")
		_ = writer.Flush()

		line, err := reader.ReadString('\n')
		if err != nil {
			return "", "", false
		}
		uStr = strings.TrimRight(line, "\r\n")
	}

	if uStr == "*" {
		return "", "", false
	}

	uDec, err := base64.StdEncoding.DecodeString(uStr)
	if err != nil {
		return "", "", false
	}
	username := string(uDec)

	// Challenge for Password (base64 of "Password:")
	_, _ = writer.WriteString("+ UGFzc3dvcmQ6\r\n")
	_ = writer.Flush()

	pLine, err := reader.ReadString('\n')
	if err != nil {
		return "", "", false
	}
	pStr := strings.TrimRight(pLine, "\r\n")
	if pStr == "*" {
		return "", "", false
	}

	pDec, err := base64.StdEncoding.DecodeString(pStr)
	if err != nil {
		return "", "", false
	}
	password := string(pDec)

	return username, password, true
}

func recordImapCredential(c *ConfIMAP, conn net.Conn, username, password, method string, tlsActive bool) {
	if c.RecordWriter == nil {
		return
	}
	pname := "imap"
	if tlsActive {
		pname = "imaps"
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
