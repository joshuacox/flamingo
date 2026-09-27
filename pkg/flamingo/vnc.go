package flamingo

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// ConfVNC contains options for the VNC (RFB) honeypot listener
type ConfVNC struct {
	BindHost     string
	BindPort     uint16
	RecordWriter *RecordWriter
	listener     net.Listener
	mu           sync.Mutex
	shutdown     bool
}

// NewConfVNC creates a default configuration for VNC listener
func NewConfVNC() *ConfVNC {
	return &ConfVNC{
		BindHost: "0.0.0.0",
		BindPort: 5900,
	}
}

// Shutdown cleanly closes the VNC listener
func (c *ConfVNC) Shutdown() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.shutdown {
		return
	}
	c.shutdown = true
	if c.listener != nil {
		_ = c.listener.Close()
	}
}

// SpawnVNC starts the VNC (RFB 003.008) honeypot listener
func SpawnVNC(conf *ConfVNC) error {
	addr := fmt.Sprintf("%s:%d", conf.BindHost, conf.BindPort)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	conf.listener = l
	conf.BindPort = uint16(l.Addr().(*net.TCPAddr).Port)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				if conf.shutdown {
					return
				}
				log.Debugf("vnc accept error: %v", err)
				return
			}
			go handleVNCConn(conn, conf)
		}
	}()

	return nil
}

func handleVNCConn(conn net.Conn, conf *ConfVNC) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	// 1. Handshake: Server sends ProtocolVersion
	serverVersion := []byte("RFB 003.008\n")
	if _, err := conn.Write(serverVersion); err != nil {
		return
	}

	// 2. Client sends ProtocolVersion (12 bytes: "RFB 003.00x\n")
	clientVersion := make([]byte, 12)
	if _, err := io.ReadFull(conn, clientVersion); err != nil {
		return
	}

	isRFB33 := string(clientVersion) == "RFB 003.003\n"

	// 3. Security Types
	if isRFB33 {
		// RFB 3.3 sends a uint32 security type (2 = VNC auth)
		if err := binary.Write(conn, binary.BigEndian, uint32(2)); err != nil {
			return
		}
	} else {
		// RFB 3.7 / 3.8: 1 byte number-of-types, followed by types
		// We offer security type 2 (VNC Authentication)
		if _, err := conn.Write([]byte{1, 2}); err != nil {
			return
		}

		// Client selects security type (1 byte)
		selectedType := make([]byte, 1)
		if _, err := io.ReadFull(conn, selectedType); err != nil {
			return
		}
		if selectedType[0] != 2 {
			// Unsupported security type requested
			return
		}
	}

	// 4. Send 16-byte random challenge
	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		return
	}
	if _, err := conn.Write(challenge); err != nil {
		return
	}

	// 5. Read 16-byte DES encrypted response from client
	response := make([]byte, 16)
	if _, err := io.ReadFull(conn, response); err != nil {
		return
	}

	// Format hash in standard Hashcat mode 14000/14100 / John format:
	// $vnc$*<challenge_hex>*<response_hex>
	hashStr := fmt.Sprintf("$vnc$*%x*%x", challenge, response)

	rec := map[string]string{
		"challenge": fmt.Sprintf("%x", challenge),
		"response":  fmt.Sprintf("%x", response),
		"password":  hashStr,
		"hash":      hashStr,
	}

	if conf.RecordWriter != nil {
		conf.RecordWriter.Record("credential", "vnc", conn.RemoteAddr().String(), rec)
	}

	// 6. Send SecurityResult: 1 (Failure)
	// uint32 1 (Failure)
	_ = binary.Write(conn, binary.BigEndian, uint32(1))

	// For RFB 3.8, if failure, also send reason string
	if !isRFB33 {
		reason := "Authentication failure"
		_ = binary.Write(conn, binary.BigEndian, uint32(len(reason)))
		_, _ = conn.Write([]byte(reason))
	}
}
