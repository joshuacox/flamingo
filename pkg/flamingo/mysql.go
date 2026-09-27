package flamingo

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

type ConfMySQL struct {
	BindHost     string
	BindPort     uint16
	Banner       string
	RecordWriter *RecordWriter
	listener     net.Listener
}

func NewConfMySQL() *ConfMySQL {
	return &ConfMySQL{
		BindHost: "0.0.0.0",
		BindPort: 3306,
		Banner:   "8.0.35",
	}
}

func (c *ConfMySQL) Shutdown() {
	if c.listener != nil {
		_ = c.listener.Close()
	}
}

func SpawnMySQL(conf *ConfMySQL) error {
	addr := fmt.Sprintf("%s:%d", conf.BindHost, conf.BindPort)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	conf.listener = l

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go handleMySQLConn(conn, conf)
		}
	}()

	return nil
}

func writeMySQLPacket(w io.Writer, seq byte, payload []byte) error {
	length := len(payload)
	header := []byte{
		byte(length & 0xff),
		byte((length >> 8) & 0xff),
		byte((length >> 16) & 0xff),
		seq,
	}
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readMySQLPacket(r io.Reader) (byte, []byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	length := int(header[0]) | (int(header[1]) << 8) | (int(header[2]) << 16)
	seq := header[3]

	if length > 16*1024*1024 {
		return 0, nil, fmt.Errorf("packet too large: %d", length)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return seq, payload, nil
}

func handleMySQLConn(conn net.Conn, conf *ConfMySQL) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	version := conf.Banner
	if version == "" {
		version = "8.0.35"
	}

	saltPart1 := []byte("12345678")
	saltPart2 := []byte("901234567890")

	// Capabilities: CLIENT_LONG_PASSWORD | CLIENT_FOUND_ROWS | CLIENT_LONG_FLAG | CLIENT_CONNECT_WITH_DB |
	// CLIENT_PROTOCOL_41 | CLIENT_INTERACTIVE | CLIENT_SECURE_CONNECTION (0x820d)
	// Upper: CLIENT_PLUGIN_AUTH (0x0008) | CLIENT_CONNECT_ATTRS (0x0010)
	capLower := uint16(0x820d)
	capUpper := uint16(0x0018)

	var greeting bytes.Buffer
	greeting.WriteByte(10) // Protocol version 10
	greeting.WriteString(version)
	greeting.WriteByte(0) // Null terminator

	_ = binary.Write(&greeting, binary.LittleEndian, uint32(1)) // Connection ID
	greeting.Write(saltPart1)
	greeting.WriteByte(0) // Filler
	_ = binary.Write(&greeting, binary.LittleEndian, capLower)
	greeting.WriteByte(33)                                    // Character set: utf8
	_ = binary.Write(&greeting, binary.LittleEndian, uint16(2)) // Status flags: SERVER_STATUS_AUTOCOMMIT
	_ = binary.Write(&greeting, binary.LittleEndian, capUpper)
	greeting.WriteByte(21)              // Auth plugin data length (8 + 12 + 1)
	greeting.Write(make([]byte, 10))    // Reserved 10 bytes
	greeting.Write(saltPart2)
	greeting.WriteByte(0) // Null terminator
	greeting.WriteString("mysql_native_password\x00")

	// Send Initial Handshake (Seq 0)
	if err := writeMySQLPacket(conn, 0, greeting.Bytes()); err != nil {
		return
	}

	// Read HandshakeResponse41 (Seq 1)
	seq, payload, err := readMySQLPacket(conn)
	if err != nil || len(payload) < 32 {
		return
	}

	clientCaps := binary.LittleEndian.Uint32(payload[:4])
	offset := 32 // skip capabilities(4), maxPacketSize(4), charset(1), reserved(23)

	// Read username (null-terminated)
	userEnd := bytes.IndexByte(payload[offset:], 0)
	if userEnd == -1 {
		return
	}
	username := string(payload[offset : offset+userEnd])
	offset += userEnd + 1

	var authData []byte
	clientSecureConn := (clientCaps & 0x00008000) != 0
	clientPluginAuthLenenc := (clientCaps & 0x00200000) != 0

	if clientPluginAuthLenenc {
		if offset < len(payload) {
			dataLen := int(payload[offset])
			offset++
			if offset+dataLen <= len(payload) {
				authData = payload[offset : offset+dataLen]
				offset += dataLen
			}
		}
	} else if clientSecureConn {
		if offset < len(payload) {
			dataLen := int(payload[offset])
			offset++
			if offset+dataLen <= len(payload) {
				authData = payload[offset : offset+dataLen]
				offset += dataLen
			}
		}
	} else {
		passEnd := bytes.IndexByte(payload[offset:], 0)
		if passEnd != -1 {
			authData = payload[offset : offset+passEnd]
			offset += passEnd + 1
		}
	}

	database := ""
	clientConnectWithDB := (clientCaps & 0x00000008) != 0
	if clientConnectWithDB && offset < len(payload) {
		dbEnd := bytes.IndexByte(payload[offset:], 0)
		if dbEnd != -1 {
			database = string(payload[offset : offset+dbEnd])
			offset += dbEnd + 1
		}
	}

	authPlugin := ""
	clientPluginAuth := (clientCaps & 0x00080000) != 0
	if clientPluginAuth && offset < len(payload) {
		pluginEnd := bytes.IndexByte(payload[offset:], 0)
		if pluginEnd != -1 {
			authPlugin = string(payload[offset : offset+pluginEnd])
		}
	}

	passwordStr := ""
	// If printable ascii characters, store as plain string; otherwise hex encode
	isPrintable := len(authData) > 0
	for _, b := range authData {
		if b < 32 || b > 126 {
			isPrintable = false
			break
		}
	}
	if isPrintable {
		passwordStr = string(authData)
	} else if len(authData) > 0 {
		passwordStr = hex.EncodeToString(authData)
	}

	rec := map[string]string{
		"username": username,
		"password": passwordStr,
	}
	if database != "" {
		rec["database"] = database
	}
	if authPlugin != "" {
		rec["auth_plugin"] = authPlugin
	}
	if conf.RecordWriter != nil {
		conf.RecordWriter.Record("credential", "mysql", conn.RemoteAddr().String(), rec)
	}

	// Send ERR_Packet
	// Header: 0xff, ErrCode uint16(1045), '#', SQLState '28000', Message
	var errPacket bytes.Buffer
	errPacket.WriteByte(0xff)
	_ = binary.Write(&errPacket, binary.LittleEndian, uint16(1045))
	errPacket.WriteByte('#')
	errPacket.WriteString("28000")
	errPacket.WriteString(fmt.Sprintf("Access denied for user '%s'@'%s' (using password: YES)", username, strings.Split(conn.RemoteAddr().String(), ":")[0]))

	_ = writeMySQLPacket(conn, seq+1, errPacket.Bytes())
}
