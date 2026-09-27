package flamingo

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestPostgresCapture(t *testing.T) {
	recordChan := make(chan map[string]string, 10)
	rw := NewRecordWriter()
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		recordChan <- rec
		return nil
	})

	conf := NewConfPostgres()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw

	if err := SpawnPostgres(conf); err != nil {
		t.Fatalf("failed to spawn postgres: %s", err)
	}
	defer conf.Shutdown()

	port := conf.listener.Addr().(*net.TCPAddr).Port

	// Case 1: Standard connection
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("failed to dial postgres: %s", err)
	}

	var startupPayload bytes.Buffer
	_ = binary.Write(&startupPayload, binary.BigEndian, int32(196608)) // Protocol 3.0
	startupPayload.WriteString("user\x00pguser\x00database\x00pgdb\x00application_name\x00psql\x00\x00")

	totalLen := int32(startupPayload.Len() + 4)
	var startupMsg bytes.Buffer
	_ = binary.Write(&startupMsg, binary.BigEndian, totalLen)
	startupMsg.Write(startupPayload.Bytes())

	if _, err := conn.Write(startupMsg.Bytes()); err != nil {
		t.Fatalf("failed to send startup: %s", err)
	}

	// Expect AuthenticationCleartextPassword ('R', len 8, code 3)
	resp := make([]byte, 9)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("failed to read auth request: %s", err)
	}
	if resp[0] != 'R' || binary.BigEndian.Uint32(resp[5:9]) != 3 {
		t.Fatalf("unexpected auth response: %v", resp)
	}

	// Send PasswordMessage ('p', len, "SuperSecret123!\x00")
	var passPayload bytes.Buffer
	passPayload.WriteString("SuperSecret123!\x00")
	var passMsg bytes.Buffer
	passMsg.WriteByte('p')
	passLen := int32(passPayload.Len() + 4)
	_ = binary.Write(&passMsg, binary.BigEndian, passLen)
	passMsg.Write(passPayload.Bytes())

	if _, err := conn.Write(passMsg.Bytes()); err != nil {
		t.Fatalf("failed to send password: %s", err)
	}

	// Read error response
	errHeader := make([]byte, 5)
	if _, err := io.ReadFull(conn, errHeader); err != nil {
		t.Fatalf("failed to read error response: %s", err)
	}
	if errHeader[0] != 'E' {
		t.Fatalf("expected ErrorResponse 'E', got %c", errHeader[0])
	}
	conn.Close()

	select {
	case rec := <-recordChan:
		if rec["_proto"] != "postgres" {
			t.Errorf("expected proto postgres, got %s", rec["_proto"])
		}
		if rec["username"] != "pguser" || rec["password"] != "SuperSecret123!" {
			t.Errorf("unexpected credentials: %v", rec)
		}
		if rec["database"] != "pgdb" || rec["application"] != "psql" {
			t.Errorf("unexpected metadata: %v", rec)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for postgres credential")
	}

	// Case 2: SSLRequest fallback
	connSSL, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("failed to dial postgres: %s", err)
	}
	defer connSSL.Close()

	// SSLRequest packet: length 8, code 80877103
	var sslReq bytes.Buffer
	_ = binary.Write(&sslReq, binary.BigEndian, int32(8))
	_ = binary.Write(&sslReq, binary.BigEndian, int32(80877103))
	_, _ = connSSL.Write(sslReq.Bytes())

	sslResp := make([]byte, 1)
	_, _ = io.ReadFull(connSSL, sslResp)
	if sslResp[0] != 'N' {
		t.Fatalf("expected 'N' to SSLRequest, got %c", sslResp[0])
	}

	// Send standard startup message after 'N'
	_, _ = connSSL.Write(startupMsg.Bytes())
	_, _ = io.ReadFull(connSSL, resp)
	_, _ = connSSL.Write(passMsg.Bytes())

	select {
	case rec := <-recordChan:
		if rec["username"] != "pguser" {
			t.Errorf("expected pguser on SSL fallback, got %s", rec["username"])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for postgres credential after SSL fallback")
	}
}

func TestMySQLCapture(t *testing.T) {
	recordChan := make(chan map[string]string, 10)
	rw := NewRecordWriter()
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		recordChan <- rec
		return nil
	})

	conf := NewConfMySQL()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.Banner = "8.0.35-honeypot"
	conf.RecordWriter = rw

	if err := SpawnMySQL(conf); err != nil {
		t.Fatalf("failed to spawn mysql: %s", err)
	}
	defer conf.Shutdown()

	port := conf.listener.Addr().(*net.TCPAddr).Port

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("failed to dial mysql: %s", err)
	}
	defer conn.Close()

	// Read Initial Handshake
	seq, payload, err := readMySQLPacket(conn)
	if err != nil {
		t.Fatalf("failed to read handshake: %s", err)
	}
	if seq != 0 {
		t.Errorf("expected sequence 0, got %d", seq)
	}
	if payload[0] != 10 {
		t.Errorf("expected protocol 10, got %d", payload[0])
	}

	// Send HandshakeResponse41
	var resp bytes.Buffer
	clientCaps := uint32(0x0020820d) // Includes CLIENT_CONNECT_WITH_DB, CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
	_ = binary.Write(&resp, binary.LittleEndian, clientCaps)
	_ = binary.Write(&resp, binary.LittleEndian, uint32(16777216)) // maxPacketSize
	resp.WriteByte(33)                                             // charset
	resp.Write(make([]byte, 23))                                   // reserved
	resp.WriteString("mysqluser\x00")                              // username
	resp.WriteByte(byte(len("MySQLP@ss123!")))                     // len-enc password length
	resp.WriteString("MySQLP@ss123!")
	resp.WriteString("production_db\x00") // database
	resp.WriteString("mysql_native_password\x00")

	if err := writeMySQLPacket(conn, 1, resp.Bytes()); err != nil {
		t.Fatalf("failed to write HandshakeResponse41: %s", err)
	}

	// Read ERR_Packet (Seq 2)
	errSeq, errPayload, err := readMySQLPacket(conn)
	if err != nil {
		t.Fatalf("failed to read ERR_Packet: %s", err)
	}
	if errSeq != 2 || errPayload[0] != 0xff {
		t.Fatalf("expected ERR_Packet with seq 2 and header 0xff, got seq %d header %x", errSeq, errPayload[0])
	}

	select {
	case rec := <-recordChan:
		if rec["_proto"] != "mysql" {
			t.Errorf("expected proto mysql, got %s", rec["_proto"])
		}
		if rec["username"] != "mysqluser" || rec["password"] != "MySQLP@ss123!" {
			t.Errorf("unexpected credentials: %v", rec)
		}
		if rec["database"] != "production_db" {
			t.Errorf("expected database production_db, got %s", rec["database"])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for mysql credential")
	}
}

func TestMongoDBCapture(t *testing.T) {
	recordChan := make(chan map[string]string, 10)
	rw := NewRecordWriter()
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		recordChan <- rec
		return nil
	})

	conf := NewConfMongoDB()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw

	if err := SpawnMongoDB(conf); err != nil {
		t.Fatalf("failed to spawn mongodb: %s", err)
	}
	defer conf.Shutdown()

	port := conf.listener.Addr().(*net.TCPAddr).Port

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("failed to dial mongodb: %s", err)
	}
	defer conn.Close()

	// 1. Send OP_MSG hello
	helloDoc := newBSONDoc()
	helloDoc.addInt32("hello", 1)
	helloDocBytes := helloDoc.finish()

	var msgBuf bytes.Buffer
	msgLen := int32(16 + 4 + 1 + len(helloDocBytes))
	_ = binary.Write(&msgBuf, binary.LittleEndian, msgLen)
	_ = binary.Write(&msgBuf, binary.LittleEndian, int32(1))    // reqID
	_ = binary.Write(&msgBuf, binary.LittleEndian, int32(0))    // respTo
	_ = binary.Write(&msgBuf, binary.LittleEndian, int32(2013)) // OP_MSG
	_ = binary.Write(&msgBuf, binary.LittleEndian, uint32(0))   // flagBits
	msgBuf.WriteByte(0)                                         // section 0
	msgBuf.Write(helloDocBytes)

	if _, err := conn.Write(msgBuf.Bytes()); err != nil {
		t.Fatalf("failed to write OP_MSG: %s", err)
	}

	respHeader := make([]byte, 16)
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		t.Fatalf("failed to read OP_MSG reply header: %s", err)
	}
	replyLen := int(binary.LittleEndian.Uint32(respHeader[0:4]))
	replyBody := make([]byte, replyLen-16)
	if _, err := io.ReadFull(conn, replyBody); err != nil {
		t.Fatalf("failed to read OP_MSG reply body: %s", err)
	}
	// section 0 BSON doc starts at index 5 (flagBits 4 + section 1)
	parsedHello := parseBSONDoc(replyBody[5:])
	if isMaster, ok := parsedHello["ismaster"].(bool); !ok || !isMaster {
		t.Fatalf("expected ismaster=true in hello reply: %v", parsedHello)
	}

	// 2. Send OP_MSG saslStart with PLAIN auth
	authDoc := newBSONDoc()
	authDoc.addInt32("saslStart", 1)
	authDoc.addString("mechanism", "PLAIN")
	authDoc.addString("$db", "admin")
	// Payload format: \x00username\x00password
	payloadBytes := []byte("\x00admin\x00MongoSuperP@ss!")
	d := &bsonDoc{}
	d.buf.Write([]byte{0, 0, 0, 0})
	d.addInt32("saslStart", 1)
	d.addString("mechanism", "PLAIN")
	d.addString("$db", "admin")
	// Add binary payload
	d.buf.WriteByte(0x05)
	d.buf.WriteString("payload\x00")
	_ = binary.Write(&d.buf, binary.LittleEndian, int32(len(payloadBytes)))
	d.buf.WriteByte(0) // binary subtype
	d.buf.Write(payloadBytes)
	authDocData := d.finish()

	var authMsg bytes.Buffer
	authMsgLen := int32(16 + 4 + 1 + len(authDocData))
	_ = binary.Write(&authMsg, binary.LittleEndian, authMsgLen)
	_ = binary.Write(&authMsg, binary.LittleEndian, int32(2))
	_ = binary.Write(&authMsg, binary.LittleEndian, int32(0))
	_ = binary.Write(&authMsg, binary.LittleEndian, int32(2013))
	_ = binary.Write(&authMsg, binary.LittleEndian, uint32(0))
	authMsg.WriteByte(0)
	authMsg.Write(authDocData)

	if _, err := conn.Write(authMsg.Bytes()); err != nil {
		t.Fatalf("failed to send saslStart: %s", err)
	}

	// Read reply
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		t.Fatalf("failed to read saslStart reply header: %s", err)
	}
	replyLen = int(binary.LittleEndian.Uint32(respHeader[0:4]))
	replyBody = make([]byte, replyLen-16)
	if _, err := io.ReadFull(conn, replyBody); err != nil {
		t.Fatalf("failed to read saslStart reply body: %s", err)
	}
	parsedAuth := parseBSONDoc(replyBody[5:])
	if okVal, ok := parsedAuth["ok"].(float64); !ok || okVal != 0.0 {
		t.Fatalf("expected ok=0.0 in auth failure reply: %v", parsedAuth)
	}

	select {
	case rec := <-recordChan:
		if rec["_proto"] != "mongodb" {
			t.Errorf("expected proto mongodb, got %s", rec["_proto"])
		}
		if rec["username"] != "admin" || rec["password"] != "MongoSuperP@ss!" {
			t.Errorf("unexpected credentials: %v", rec)
		}
		if rec["database"] != "admin" || rec["mechanism"] != "PLAIN" {
			t.Errorf("unexpected metadata: %v", rec)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for mongodb credential")
	}
}
