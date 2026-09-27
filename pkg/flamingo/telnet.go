package flamingo

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// ConfTelnet holds configuration for a Telnet capture server.
type ConfTelnet struct {
	BindPort     uint16
	BindHost     string
	Banner       string
	RecordWriter *RecordWriter
	shutdown     bool
	listener     net.Listener
	m            sync.Mutex
}

// NewConfTelnet creates a default configuration for the Telnet capture server.
func NewConfTelnet() *ConfTelnet {
	return &ConfTelnet{
		BindPort: 23,
		BindHost: "[::]",
		Banner:   "Flamingo Honeypot Telnet Service\r\n",
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfTelnet) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfTelnet) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	if !c.shutdown {
		c.shutdown = true
		if c.listener != nil {
			c.listener.Close()
		}
	}
}

// SpawnTelnet creates and starts a new Telnet capture server.
func SpawnTelnet(c *ConfTelnet) error {
	addr := fmt.Sprintf("%s:%d", c.BindHost, c.BindPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	log.Debugf("telnet is listening on %s", addr)
	c.listener = listener
	go telnetAcceptLoop(c)
	return nil
}

func telnetAcceptLoop(c *ConfTelnet) {
	for !c.IsShutdown() {
		conn, err := c.listener.Accept()
		if err != nil {
			continue
		}
		go telnetHandleConnection(c, conn)
	}
}

func telnetHandleConnection(c *ConfTelnet, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))

	// Send basic IAC negotiation: IAC WILL ECHO, IAC WILL SUPPRESS_GO_AHEAD
	_, _ = conn.Write([]byte{255, 251, 1, 255, 251, 3})

	banner := c.Banner
	if banner == "" {
		banner = "Flamingo Honeypot Telnet Service\r\n"
	}
	_, _ = conn.Write([]byte(banner))

	reader := bufio.NewReader(conn)

	for attempt := 0; attempt < 3; attempt++ {
		_, _ = conn.Write([]byte("login: "))
		user, err := readTelnetLine(reader)
		if err != nil {
			return
		}

		_, _ = conn.Write([]byte("Password: "))
		pass, err := readTelnetLine(reader)
		if err != nil {
			return
		}

		user = strings.TrimSpace(user)
		pass = strings.TrimSpace(pass)

		if user != "" || pass != "" {
			if c.RecordWriter != nil {
				c.RecordWriter.Record(
					"credential",
					"telnet",
					conn.RemoteAddr().String(),
					map[string]string{
						"username": user,
						"password": pass,
						"method":   "telnet",
						"_server":  fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
					},
				)
			}
		}

		_, _ = conn.Write([]byte("\r\nLogin incorrect\r\n\r\n"))
	}
}

func readTelnetLine(reader *bufio.Reader) (string, error) {
	var line strings.Builder
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return "", err
		}

		// Handle Telnet IAC escape sequence (255 ...)
		if b == 255 {
			cmd, err := reader.ReadByte()
			if err != nil {
				return "", err
			}
			if cmd >= 251 && cmd <= 254 {
				// DO/DONT/WILL/WONT + option
				_, _ = reader.ReadByte()
			}
			continue
		}

		if b == '\r' {
			next, err := reader.Peek(1)
			if err == nil && len(next) > 0 && (next[0] == '\n' || next[0] == 0) {
				_, _ = reader.ReadByte()
			}
			break
		}
		if b == '\n' {
			break
		}
		if b == '\b' || b == 127 {
			// backspace
			str := line.String()
			if len(str) > 0 {
				line.Reset()
				line.WriteString(str[:len(str)-1])
			}
			continue
		}

		line.WriteByte(b)
	}
	return line.String(), nil
}
