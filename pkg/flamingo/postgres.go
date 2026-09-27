package flamingo

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

type ConfPostgres struct {
	BindHost     string
	BindPort     uint16
	RecordWriter *RecordWriter
	listener     net.Listener
}

func NewConfPostgres() *ConfPostgres {
	return &ConfPostgres{
		BindHost: "0.0.0.0",
		BindPort: 5432,
	}
}

func (c *ConfPostgres) Shutdown() {
	if c.listener != nil {
		_ = c.listener.Close()
	}
}

func SpawnPostgres(conf *ConfPostgres) error {
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
			go handlePostgresConn(conn, conf)
		}
	}()

	return nil
}

func handlePostgresConn(conn net.Conn, conf *ConfPostgres) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	// Read initial message (could be SSLRequest or StartupMessage)
	var length int32
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return
	}
	if length < 8 || length > 10000 {
		return
	}

	payload := make([]byte, length-4)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return
	}

	code := binary.BigEndian.Uint32(payload[:4])

	// Check for SSLRequest (code 80877103 = 0x04D2162F)
	if code == 80877103 {
		// Send 'N' to indicate SSL is not supported, forcing client to fallback to plain StartupMessage
		if _, err := conn.Write([]byte{'N'}); err != nil {
			return
		}

		// Read the subsequent StartupMessage
		if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
			return
		}
		if length < 8 || length > 10000 {
			return
		}
		payload = make([]byte, length-4)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return
		}
		code = binary.BigEndian.Uint32(payload[:4])
	}

	// Protocol version 3.0 is 196608 (0x00030000)
	if code != 196608 {
		return
	}

	// Parse parameters (null-terminated strings until a zero byte)
	params := make(map[string]string)
	paramBytes := payload[4:]
	for len(paramBytes) > 0 {
		if paramBytes[0] == 0 {
			break
		}
		idx1 := bytes.IndexByte(paramBytes, 0)
		if idx1 == -1 {
			break
		}
		k := string(paramBytes[:idx1])
		paramBytes = paramBytes[idx1+1:]

		idx2 := bytes.IndexByte(paramBytes, 0)
		if idx2 == -1 {
			break
		}
		v := string(paramBytes[:idx2])
		paramBytes = paramBytes[idx2+1:]

		params[k] = v
	}

	user := params["user"]
	database := params["database"]
	app := params["application_name"]

	// Request cleartext password (AuthenticationCleartextPassword)
	// Byte1('R') + Int32(8) + Int32(3)
	authReq := []byte{'R', 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x03}
	if _, err := conn.Write(authReq); err != nil {
		return
	}

	// Read client's PasswordMessage: Byte1('p') + Int32(Length) + PasswordString + Byte1(0)
	var msgType [1]byte
	if _, err := io.ReadFull(conn, msgType[:]); err != nil {
		return
	}
	if msgType[0] != 'p' {
		return
	}

	var passMsgLen int32
	if err := binary.Read(conn, binary.BigEndian, &passMsgLen); err != nil {
		return
	}
	if passMsgLen < 5 || passMsgLen > 10000 {
		return
	}

	passBytes := make([]byte, passMsgLen-4)
	if _, err := io.ReadFull(conn, passBytes); err != nil {
		return
	}

	password := strings.TrimRight(string(passBytes), "\x00")

	// Record captured credential
	rec := map[string]string{
		"username": user,
		"password": password,
	}
	if database != "" {
		rec["database"] = database
	}
	if app != "" {
		rec["application"] = app
	}
	if conf.RecordWriter != nil {
		conf.RecordWriter.Record("credential", "postgres", conn.RemoteAddr().String(), rec)
	}

	// Send ErrorResponse ('E')
	var errPayload bytes.Buffer
	errPayload.WriteByte('S')
	errPayload.WriteString("FATAL\x00")
	errPayload.WriteByte('V')
	errPayload.WriteString("FATAL\x00")
	errPayload.WriteByte('C')
	errPayload.WriteString("28P01\x00")
	errPayload.WriteByte('M')
	errPayload.WriteString(fmt.Sprintf("password authentication failed for user \"%s\"\x00", user))
	errPayload.WriteByte(0)

	var errBuf bytes.Buffer
	errBuf.WriteByte('E')
	errLen := int32(errPayload.Len() + 4)
	_ = binary.Write(&errBuf, binary.BigEndian, errLen)
	errBuf.Write(errPayload.Bytes())

	_, _ = conn.Write(errBuf.Bytes())
}
