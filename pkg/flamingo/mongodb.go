package flamingo

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"time"
)

type ConfMongoDB struct {
	BindHost     string
	BindPort     uint16
	RecordWriter *RecordWriter
	listener     net.Listener
}

func NewConfMongoDB() *ConfMongoDB {
	return &ConfMongoDB{
		BindHost: "0.0.0.0",
		BindPort: 27017,
	}
}

func (c *ConfMongoDB) Shutdown() {
	if c.listener != nil {
		_ = c.listener.Close()
	}
}

func SpawnMongoDB(conf *ConfMongoDB) error {
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
			go handleMongoDBConn(conn, conf)
		}
	}()

	return nil
}

// Minimal BSON document builder
type bsonDoc struct {
	buf bytes.Buffer
}

func newBSONDoc() *bsonDoc {
	d := &bsonDoc{}
	// reserve 4 bytes for length
	d.buf.Write([]byte{0, 0, 0, 0})
	return d
}

func (d *bsonDoc) addBool(name string, val bool) {
	d.buf.WriteByte(0x08)
	d.buf.WriteString(name)
	d.buf.WriteByte(0)
	if val {
		d.buf.WriteByte(1)
	} else {
		d.buf.WriteByte(0)
	}
}

func (d *bsonDoc) addDouble(name string, val float64) {
	d.buf.WriteByte(0x01)
	d.buf.WriteString(name)
	d.buf.WriteByte(0)
	bits := math.Float64bits(val)
	_ = binary.Write(&d.buf, binary.LittleEndian, bits)
}

func (d *bsonDoc) addInt32(name string, val int32) {
	d.buf.WriteByte(0x10)
	d.buf.WriteString(name)
	d.buf.WriteByte(0)
	_ = binary.Write(&d.buf, binary.LittleEndian, val)
}

func (d *bsonDoc) addString(name string, val string) {
	d.buf.WriteByte(0x02)
	d.buf.WriteString(name)
	d.buf.WriteByte(0)
	strLen := int32(len(val) + 1)
	_ = binary.Write(&d.buf, binary.LittleEndian, strLen)
	d.buf.WriteString(val)
	d.buf.WriteByte(0)
}

func (d *bsonDoc) finish() []byte {
	d.buf.WriteByte(0) // terminator
	res := d.buf.Bytes()
	binary.LittleEndian.PutUint32(res[:4], uint32(len(res)))
	return res
}

// Simple BSON map parser
func parseBSONDoc(data []byte) map[string]any {
	res := make(map[string]any)
	if len(data) < 5 {
		return res
	}
	docLen := int(binary.LittleEndian.Uint32(data[:4]))
	if docLen > len(data) {
		docLen = len(data)
	}
	idx := 4
	for idx < docLen-1 {
		elemType := data[idx]
		idx++
		nameEnd := bytes.IndexByte(data[idx:docLen], 0)
		if nameEnd == -1 {
			break
		}
		name := string(data[idx : idx+nameEnd])
		idx += nameEnd + 1

		switch elemType {
		case 0x01: // Double
			if idx+8 <= docLen {
				bits := binary.LittleEndian.Uint64(data[idx : idx+8])
				res[name] = math.Float64frombits(bits)
				idx += 8
			}
		case 0x02: // String
			if idx+4 <= docLen {
				sLen := int(binary.LittleEndian.Uint32(data[idx : idx+4]))
				idx += 4
				if idx+sLen <= docLen {
					res[name] = string(data[idx : idx+sLen-1])
					idx += sLen
				}
			}
		case 0x03: // Embedded Document
			if idx+4 <= docLen {
				subLen := int(binary.LittleEndian.Uint32(data[idx : idx+4]))
				if idx+subLen <= docLen {
					res[name] = parseBSONDoc(data[idx : idx+subLen])
					idx += subLen
				}
			}
		case 0x04: // Array
			if idx+4 <= docLen {
				subLen := int(binary.LittleEndian.Uint32(data[idx : idx+4]))
				idx += subLen
			}
		case 0x05: // Binary
			if idx+5 <= docLen {
				bLen := int(binary.LittleEndian.Uint32(data[idx : idx+4]))
				idx += 5 // length + subtype
				if idx+bLen <= docLen {
					res[name] = data[idx : idx+bLen]
					idx += bLen
				}
			}
		case 0x08: // Boolean
			if idx < docLen {
				res[name] = data[idx] != 0
				idx++
			}
		case 0x10: // Int32
			if idx+4 <= docLen {
				res[name] = int32(binary.LittleEndian.Uint32(data[idx : idx+4]))
				idx += 4
			}
		case 0x12: // Int64
			if idx+8 <= docLen {
				res[name] = int64(binary.LittleEndian.Uint64(data[idx : idx+8]))
				idx += 8
			}
		default:
			return res
		}
	}
	return res
}

func handleMongoDBConn(conn net.Conn, conf *ConfMongoDB) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	header := make([]byte, 16)
	for {
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		msgLen := int(binary.LittleEndian.Uint32(header[0:4]))
		reqID := int32(binary.LittleEndian.Uint32(header[4:8]))
		opCode := int32(binary.LittleEndian.Uint32(header[12:16]))

		if msgLen < 16 || msgLen > 16*1024*1024 {
			return
		}

		body := make([]byte, msgLen-16)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}

		if opCode == 2013 { // OP_MSG
			if len(body) < 5 {
				return
			}
			// flagBits := binary.LittleEndian.Uint32(body[0:4])
			// Section 0: kind byte (0) + BSON document
			if body[4] == 0 {
				docBytes := body[5:]
				doc := parseBSONDoc(docBytes)
				respDoc := handleMongoCommand(doc, conn.RemoteAddr().String(), conf)

				// Reply with OP_MSG
				docData := respDoc.finish()
				replyMsgLen := 16 + 4 + 1 + len(docData)
				var reply bytes.Buffer
				_ = binary.Write(&reply, binary.LittleEndian, int32(replyMsgLen))
				_ = binary.Write(&reply, binary.LittleEndian, int32(1000))
				_ = binary.Write(&reply, binary.LittleEndian, reqID)
				_ = binary.Write(&reply, binary.LittleEndian, int32(2013))
				_ = binary.Write(&reply, binary.LittleEndian, uint32(0)) // flagBits
				reply.WriteByte(0)                                      // Section 0
				reply.Write(docData)
				if _, err := conn.Write(reply.Bytes()); err != nil {
					return
				}
			}
		} else if opCode == 2004 { // OP_QUERY
			// flags(4), cstring, skip(4), return(4), query(bson)
			idx := 4
			collEnd := bytes.IndexByte(body[idx:], 0)
			if collEnd != -1 {
				idx += collEnd + 1 + 8 // skip name, skip, return
				if idx < len(body) {
					doc := parseBSONDoc(body[idx:])
					respDoc := handleMongoCommand(doc, conn.RemoteAddr().String(), conf)

					docData := respDoc.finish()
					replyMsgLen := 16 + 20 + len(docData)
					var reply bytes.Buffer
					_ = binary.Write(&reply, binary.LittleEndian, int32(replyMsgLen))
					_ = binary.Write(&reply, binary.LittleEndian, int32(1001))
					_ = binary.Write(&reply, binary.LittleEndian, reqID)
					_ = binary.Write(&reply, binary.LittleEndian, int32(1)) // OP_REPLY
					_ = binary.Write(&reply, binary.LittleEndian, int32(0)) // responseFlags
					_ = binary.Write(&reply, binary.LittleEndian, int64(0)) // cursorID
					_ = binary.Write(&reply, binary.LittleEndian, int32(0)) // startingFrom
					_ = binary.Write(&reply, binary.LittleEndian, int32(1)) // numberReturned
					reply.Write(docData)
					if _, err := conn.Write(reply.Bytes()); err != nil {
						return
					}
				}
			}
		} else {
			return
		}
	}
}

func handleMongoCommand(doc map[string]any, remoteAddr string, conf *ConfMongoDB) *bsonDoc {
	resp := newBSONDoc()

	// Check if this is an auth command
	if saslStart, ok := doc["saslStart"]; ok && saslStart != nil {
		mech, _ := doc["mechanism"].(string)
		db, _ := doc["$db"].(string)
		user := ""
		password := ""

		if payloadBytes, ok := doc["payload"].([]byte); ok {
			pStr := string(payloadBytes)
			// SCRAM client-first-message: e.g., n,,n=user,r=nonce
			if strings.HasPrefix(pStr, "n,") || strings.HasPrefix(pStr, "y,") {
				parts := strings.Split(pStr, ",")
				for _, part := range parts {
					if strings.HasPrefix(part, "n=") {
						user = strings.TrimPrefix(part, "n=")
					}
				}
				password = pStr
			} else if mech == "PLAIN" {
				// PLAIN payload format (RFC 4616): [authzid] \x00 authcid \x00 passwd
				plainParts := strings.Split(pStr, "\x00")
				if len(plainParts) >= 3 {
					if plainParts[0] == "" {
						user = plainParts[1]
						password = plainParts[2]
					} else {
						user = plainParts[1]
						password = plainParts[2]
					}
				} else if len(plainParts) == 2 {
					user = plainParts[0]
					password = plainParts[1]
				}
			}
		}

		if user != "" || password != "" {
			rec := map[string]string{
				"username": user,
				"password": password,
			}
			if db != "" {
				rec["database"] = db
			}
			if mech != "" {
				rec["mechanism"] = mech
			}
			if conf.RecordWriter != nil {
				conf.RecordWriter.Record("credential", "mongodb", remoteAddr, rec)
			}
		}

		// Return auth failure
		resp.addDouble("ok", 0.0)
		resp.addInt32("code", 18)
		resp.addString("codeName", "AuthenticationFailed")
		resp.addString("errmsg", "Authentication failed.")
		return resp
	}

	if authCmd, ok := doc["authenticate"]; ok && authCmd != nil {
		user, _ := doc["user"].(string)
		pwd, _ := doc["pwd"].(string)
		if pwd == "" {
			pwd, _ = doc["key"].(string)
		}
		db, _ := doc["$db"].(string)

		rec := map[string]string{
			"username": user,
			"password": pwd,
		}
		if db != "" {
			rec["database"] = db
		}
		if conf.RecordWriter != nil {
			conf.RecordWriter.Record("credential", "mongodb", remoteAddr, rec)
		}

		resp.addDouble("ok", 0.0)
		resp.addInt32("code", 18)
		resp.addString("codeName", "AuthenticationFailed")
		resp.addString("errmsg", "Authentication failed.")
		return resp
	}

	// Standard handshake response for hello / isMaster / buildInfo
	resp.addBool("ismaster", true)
	resp.addBool("isWritablePrimary", true)
	resp.addInt32("maxBsonObjectSize", 16777216)
	resp.addInt32("maxMessageSizeBytes", 48000000)
	resp.addInt32("maxWriteBatchSize", 100000)
	resp.addInt32("minWireVersion", 0)
	resp.addInt32("maxWireVersion", 17)
	resp.addBool("readOnly", false)
	resp.addDouble("ok", 1.0)
	return resp
}
