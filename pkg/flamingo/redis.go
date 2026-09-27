package flamingo

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// ConfRedis holds configuration for a Redis capture server.
type ConfRedis struct {
	BindPort     uint16
	BindHost     string
	RecordWriter *RecordWriter
	shutdown     bool
	listener     net.Listener
	m            sync.Mutex
}

// NewConfRedis creates a default configuration for the Redis capture server.
func NewConfRedis() *ConfRedis {
	return &ConfRedis{
		BindPort: 6379,
		BindHost: "[::]",
	}
}

// IsShutdown checks to see if the service is shutting down.
func (c *ConfRedis) IsShutdown() bool {
	c.m.Lock()
	defer c.m.Unlock()
	return c.shutdown
}

// Shutdown flags the service to shut down.
func (c *ConfRedis) Shutdown() {
	c.m.Lock()
	defer c.m.Unlock()
	if !c.shutdown {
		c.shutdown = true
		if c.listener != nil {
			c.listener.Close()
		}
	}
}

// SpawnRedis creates and starts a new Redis capture server.
func SpawnRedis(c *ConfRedis) error {
	addr := fmt.Sprintf("%s:%d", c.BindHost, c.BindPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	log.Debugf("redis is listening on %s", addr)
	c.listener = listener
	go redisAcceptLoop(c)
	return nil
}

func redisAcceptLoop(c *ConfRedis) {
	for !c.IsShutdown() {
		conn, err := c.listener.Accept()
		if err != nil {
			continue
		}
		go redisHandleConnection(c, conn)
	}
}

func redisHandleConnection(c *ConfRedis, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	for {
		// Read line or RESP frame
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}

		var args []string

		// RESP Array: *<count>\r\n$<len>\r\n<arg>\r\n...
		if strings.HasPrefix(line, "*") {
			count, err := strconv.Atoi(line[1:])
			if err != nil || count <= 0 {
				_, _ = writer.WriteString("-ERR Protocol error\r\n")
				_ = writer.Flush()
				continue
			}

			for i := 0; i < count; i++ {
				lenLine, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				lenLine = strings.TrimRight(lenLine, "\r\n")
				if !strings.HasPrefix(lenLine, "$") {
					break
				}
				argLen, err := strconv.Atoi(lenLine[1:])
				if err != nil || argLen < 0 {
					break
				}

				argBuf := make([]byte, argLen+2) // data + \r\n
				total := 0
				for total < len(argBuf) {
					n, err := reader.Read(argBuf[total:])
					if err != nil {
						return
					}
					total += n
				}
				args = append(args, string(argBuf[:argLen]))
			}
		} else {
			// Inline command: AUTH <pass> or PING
			args = strings.Fields(line)
		}

		if len(args) == 0 {
			continue
		}

		cmd := strings.ToUpper(args[0])
		switch cmd {
		case "AUTH":
			username := "default"
			password := ""
			if len(args) == 2 {
				// Classic Redis: AUTH <password>
				password = args[1]
			} else if len(args) >= 3 {
				// Redis 6 ACL: AUTH <username> <password>
				username = args[1]
				password = args[2]
			}

			if c.RecordWriter != nil {
				c.RecordWriter.Record(
					"credential",
					"redis",
					conn.RemoteAddr().String(),
					map[string]string{
						"username": username,
						"password": password,
						"method":   "auth",
						"_server":  fmt.Sprintf("%s:%d", c.BindHost, c.BindPort),
					},
				)
			}
			// Respond with authentication error
			_, _ = writer.WriteString("-WRONGPASS invalid username-password pair or user is disabled.\r\n")
			_ = writer.Flush()

		case "PING":
			_, _ = writer.WriteString("+PONG\r\n")
			_ = writer.Flush()

		case "QUIT":
			_, _ = writer.WriteString("+OK\r\n")
			_ = writer.Flush()
			return

		case "INFO":
			infoMsg := "# Server\r\nredis_version:7.2.4\r\nos:Linux\r\ntcp_port:6379\r\n"
			_, _ = writer.WriteString(fmt.Sprintf("$%d\r\n%s\r\n", len(infoMsg), infoMsg))
			_ = writer.Flush()

		case "COMMAND":
			_, _ = writer.WriteString("*0\r\n")
			_ = writer.Flush()

		default:
			_, _ = writer.WriteString("-NOAUTH Authentication required.\r\n")
			_ = writer.Flush()
		}
	}
}
