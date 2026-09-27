package flamingo

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// ConfMQTT contains configuration for MQTT / MQTTS honeypot
type ConfMQTT struct {
	BindHost     string
	BindPort     uint16
	TLS          bool
	TLSCert      string
	TLSKey       string
	TLSName      string
	TLSConfig    *tls.Config
	RecordWriter *RecordWriter
	listener     net.Listener
	mu           sync.Mutex
	shutdown     bool
}

// NewConfMQTT creates a default configuration for MQTT listener
func NewConfMQTT() *ConfMQTT {
	return &ConfMQTT{
		BindHost: "0.0.0.0",
		BindPort: 1883,
	}
}

// Shutdown cleanly stops the MQTT listener
func (c *ConfMQTT) Shutdown() {
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

// SpawnMQTT starts the MQTT honeypot listener
func SpawnMQTT(conf *ConfMQTT) error {
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
				return fmt.Errorf("failed to load tls cert for mqtt on %s:%d: %w", conf.BindHost, conf.BindPort, err)
			}
			tlsCfg.Certificates = []tls.Certificate{kp}
			conf.TLSConfig = GlobalTLSRegistry.WrapTLSConfig(tlsCfg)
		}
		if conf.TLSConfig != nil {
			l = tls.NewListener(l, conf.TLSConfig)
		}
	}

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				if conf.shutdown {
					return
				}
				log.Debugf("mqtt accept error: %v", err)
				return
			}
			go handleMQTTConn(conn, conf)
		}
	}()

	return nil
}

func handleMQTTConn(conn net.Conn, conf *ConfMQTT) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	pname := "mqtt"
	if conf.TLS {
		pname = "mqtts"
	}

	// 1. Read fixed header byte 1 (Packet type & flags)
	hdr := make([]byte, 1)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}

	packetType := (hdr[0] >> 4) & 0x0F
	if packetType != 1 { // 1 = CONNECT
		return
	}

	// 2. Read Remaining Length (variable byte integer: 1 to 4 bytes)
	multiplier := 1
	remLen := 0
	for i := 0; i < 4; i++ {
		b := make([]byte, 1)
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		remLen += int(b[0]&0x7F) * multiplier
		if (b[0] & 0x80) == 0 {
			break
		}
		multiplier *= 128
	}

	if remLen <= 0 || remLen > 1024*1024 {
		return
	}

	// 3. Read variable header and payload
	body := make([]byte, remLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return
	}

	// Parse variable header:
	// Protocol Name: 2-byte length + string
	offset := 0
	if len(body) < 2 {
		return
	}
	protoNameLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if len(body) < offset+protoNameLen+4 { // protoName + version (1) + flags (1) + keepalive (2)
		return
	}
	protoName := string(body[offset : offset+protoNameLen])
	offset += protoNameLen

	protoVersion := body[offset]
	offset++

	connectFlags := body[offset]
	offset++

	hasUsername := (connectFlags & 0x80) != 0
	hasPassword := (connectFlags & 0x40) != 0
	hasWill := (connectFlags & 0x04) != 0
	cleanSession := (connectFlags & 0x02) != 0

	keepAlive := binary.BigEndian.Uint16(body[offset : offset+2])
	offset += 2

	// If MQTT 5.0 (version 5), skip properties
	if protoVersion == 5 {
		if offset < len(body) {
			propLen, n := decodeVariableLength(body[offset:])
			offset += n + propLen
		}
	}

	// Parse Payload
	// 1. Client Identifier
	clientID := ""
	if offset+2 <= len(body) {
		idLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
		offset += 2
		if offset+idLen <= len(body) {
			clientID = string(body[offset : offset+idLen])
			offset += idLen
		}
	}

	// 2. Will topic and message (if will flag)
	if hasWill {
		if offset+2 <= len(body) {
			topicLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
			offset += 2 + topicLen
		}
		if offset+2 <= len(body) {
			msgLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
			offset += 2 + msgLen
		}
	}

	// 3. Username
	username := ""
	if hasUsername && offset+2 <= len(body) {
		userLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
		offset += 2
		if offset+userLen <= len(body) {
			username = string(body[offset : offset+userLen])
			offset += userLen
		}
	}

	// 4. Password
	password := ""
	if hasPassword && offset+2 <= len(body) {
		passLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
		offset += 2
		if offset+passLen <= len(body) {
			password = string(body[offset : offset+passLen])
			offset += passLen
		}
	}

	rec := map[string]string{
		"client_id":        clientID,
		"username":         username,
		"password":         password,
		"keep_alive":       fmt.Sprintf("%d", keepAlive),
		"clean_session":    fmt.Sprintf("%t", cleanSession),
		"protocol":         protoName,
		"protocol_version": fmt.Sprintf("%d", protoVersion),
	}

	if conf.RecordWriter != nil {
		conf.RecordWriter.Record("credential", pname, conn.RemoteAddr().String(), rec)
	}

	// Respond with CONNACK (0x20):
	if protoVersion == 5 {
		// MQTT 5 CONNACK: Fixed Header 0x20 0x03, Variable Header: Flags 0x00, Reason Code 0x86 (bad user/pass), Properties Length 0x00
		_, _ = conn.Write([]byte{0x20, 0x03, 0x00, 0x86, 0x00})
	} else {
		// MQTT 3.1 / 3.1.1 CONNACK: Fixed Header 0x20 0x02, Variable Header: Flags 0x00, Return Code 0x04 (Bad username or password)
		_, _ = conn.Write([]byte{0x20, 0x02, 0x00, 0x04})
	}
}

func decodeVariableLength(data []byte) (val int, bytesRead int) {
	multiplier := 1
	for i, b := range data {
		val += int(b&0x7F) * multiplier
		bytesRead = i + 1
		if (b & 0x80) == 0 {
			break
		}
		multiplier *= 128
		if i >= 3 {
			break
		}
	}
	return val, bytesRead
}
