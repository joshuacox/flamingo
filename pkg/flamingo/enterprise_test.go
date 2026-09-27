package flamingo

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestSMBCapture(t *testing.T) {
	recordChan := make(chan map[string]string, 10)
	rw := NewRecordWriter()
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		recordChan <- rec
		return nil
	})

	conf := NewConfSMB()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw

	if err := SpawnSMB(conf); err != nil {
		t.Fatalf("failed to spawn smb: %s", err)
	}
	defer conf.Shutdown()

	port := conf.listener.Addr().(*net.TCPAddr).Port

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("failed to dial smb: %s", err)
	}
	defer conn.Close()

	// 1. Send SMB2 NEGOTIATE
	negHdr := buildSMB2Header(0, 0, 1, 0)
	negBody := make([]byte, 36)
	binary.LittleEndian.PutUint16(negBody[0:2], 36)     // StructureSize
	binary.LittleEndian.PutUint16(negBody[2:4], 1)      // DialectCount
	binary.LittleEndian.PutUint16(negBody[4:6], 0x0202) // Dialect SMB 2.0.2

	negPacket := append(negHdr, negBody...)
	if err := writeNetBIOSPacket(conn, negPacket); err != nil {
		t.Fatalf("failed to send smb negotiate: %s", err)
	}

	negResp, err := readNetBIOSPacket(conn)
	if err != nil || len(negResp) < 64 {
		t.Fatalf("failed to read smb negotiate response: %s", err)
	}
	if negResp[0] != 0xfe || negResp[1] != 'S' || negResp[2] != 'M' || negResp[3] != 'B' {
		t.Fatalf("invalid smb2 header magic: %v", negResp[:4])
	}

	// 2. Send SMB2 SESSION SETUP (Type 1 NTLMSSP)
	setupHdr := buildSMB2Header(0, 1, 2, 0)
	var type1 bytes.Buffer
	type1.WriteString("NTLMSSP\x00")
	_ = binary.Write(&type1, binary.LittleEndian, uint32(1)) // Type 1
	_ = binary.Write(&type1, binary.LittleEndian, uint32(0x00028205))
	type1Payload := type1.Bytes()

	setupBody := make([]byte, 24)
	binary.LittleEndian.PutUint16(setupBody[0:2], 25) // StructureSize
	binary.LittleEndian.PutUint16(setupBody[12:14], 88)
	binary.LittleEndian.PutUint16(setupBody[14:16], uint16(len(type1Payload)))

	var setupPacket bytes.Buffer
	setupPacket.Write(setupHdr)
	setupPacket.Write(setupBody)
	setupPacket.Write(type1Payload)

	if err := writeNetBIOSPacket(conn, setupPacket.Bytes()); err != nil {
		t.Fatalf("failed to send smb session setup type 1: %s", err)
	}

	// Read Type 2 challenge response
	setupResp, err := readNetBIOSPacket(conn)
	if err != nil || len(setupResp) < 64 {
		t.Fatalf("failed to read session setup type 2: %s", err)
	}
	status := binary.LittleEndian.Uint32(setupResp[8:12])
	if status != 0xc0000016 { // STATUS_MORE_PROCESSING_REQUIRED
		t.Fatalf("expected STATUS_MORE_PROCESSING_REQUIRED (0xc0000016), got 0x%x", status)
	}

	// 3. Send SMB2 SESSION SETUP (Type 3 NTLMSSP Authenticate)
	setupHdr3 := buildSMB2Header(0, 1, 3, 0x1000)
	lmResp := make([]byte, 24)
	ntResp := bytes.Repeat([]byte{0xaa}, 24)
	toUTF16LE := func(s string) []byte {
		b := make([]byte, len(s)*2)
		for i, r := range s {
			b[i*2] = byte(r)
			b[i*2+1] = 0
		}
		return b
	}
	domain := toUTF16LE("CORP")
	user := toUTF16LE("DomainAdmin")
	ws := toUTF16LE("WORKSTATION1")

	lmOffset := uint32(64)
	ntOffset := lmOffset + uint32(len(lmResp))
	domainOffset := ntOffset + uint32(len(ntResp))
	userOffset := domainOffset + uint32(len(domain))
	wsOffset := userOffset + uint32(len(user))

	var type3 bytes.Buffer
	type3.WriteString("NTLMSSP\x00")
	_ = binary.Write(&type3, binary.LittleEndian, uint32(3)) // Type 3

	// LmChallengeResponseFields (12..19)
	_ = binary.Write(&type3, binary.LittleEndian, uint16(len(lmResp)))
	_ = binary.Write(&type3, binary.LittleEndian, uint16(len(lmResp)))
	_ = binary.Write(&type3, binary.LittleEndian, lmOffset)

	// NtChallengeResponseFields (20..27)
	_ = binary.Write(&type3, binary.LittleEndian, uint16(len(ntResp)))
	_ = binary.Write(&type3, binary.LittleEndian, uint16(len(ntResp)))
	_ = binary.Write(&type3, binary.LittleEndian, ntOffset)

	// DomainNameFields (28..35)
	_ = binary.Write(&type3, binary.LittleEndian, uint16(len(domain)))
	_ = binary.Write(&type3, binary.LittleEndian, uint16(len(domain)))
	_ = binary.Write(&type3, binary.LittleEndian, domainOffset)

	// UserNameFields (36..43)
	_ = binary.Write(&type3, binary.LittleEndian, uint16(len(user)))
	_ = binary.Write(&type3, binary.LittleEndian, uint16(len(user)))
	_ = binary.Write(&type3, binary.LittleEndian, userOffset)

	// WorkstationFields (44..51)
	_ = binary.Write(&type3, binary.LittleEndian, uint16(len(ws)))
	_ = binary.Write(&type3, binary.LittleEndian, uint16(len(ws)))
	_ = binary.Write(&type3, binary.LittleEndian, wsOffset)

	// EncryptedRandomSessionKeyFields (52..59)
	_ = binary.Write(&type3, binary.LittleEndian, uint16(0))
	_ = binary.Write(&type3, binary.LittleEndian, uint16(0))
	_ = binary.Write(&type3, binary.LittleEndian, uint32(0))

	// NegotiateFlags (60..63)
	_ = binary.Write(&type3, binary.LittleEndian, uint32(0x00028205))

	// Append payloads starting at offset 64
	type3.Write(lmResp)
	type3.Write(ntResp)
	type3.Write(domain)
	type3.Write(user)
	type3.Write(ws)

	type3Payload := type3.Bytes()
	var setupPacket3 bytes.Buffer
	setupPacket3.Write(setupHdr3)
	setupBody3 := make([]byte, 24)
	binary.LittleEndian.PutUint16(setupBody3[0:2], 25)
	binary.LittleEndian.PutUint16(setupBody3[12:14], 88)
	binary.LittleEndian.PutUint16(setupBody3[14:16], uint16(len(type3Payload)))
	setupPacket3.Write(setupBody3)
	setupPacket3.Write(type3Payload)

	if err := writeNetBIOSPacket(conn, setupPacket3.Bytes()); err != nil {
		t.Fatalf("failed to send smb session setup type 3: %s", err)
	}

	// Read logon failure response
	failResp, err := readNetBIOSPacket(conn)
	if err != nil || len(failResp) < 12 {
		t.Fatalf("failed to read logon failure response: %s", err)
	}
	failStatus := binary.LittleEndian.Uint32(failResp[8:12])
	if failStatus != 0xc000006d { // STATUS_LOGON_FAILURE
		t.Fatalf("expected STATUS_LOGON_FAILURE (0xc000006d), got 0x%x", failStatus)
	}

	select {
	case rec := <-recordChan:
		if rec["_proto"] != "smb" {
			t.Errorf("expected proto smb, got %s", rec["_proto"])
		}
		if rec["username"] != "DomainAdmin" || rec["domain"] != "CORP" {
			t.Errorf("unexpected credentials: %v", rec)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for smb credential")
	}
}

func TestWinRMCapture(t *testing.T) {
	recordChan := make(chan map[string]string, 10)
	rw := NewRecordWriter()
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		recordChan <- rec
		return nil
	})

	conf := NewConfWinRM()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw

	if err := SpawnWinRM(conf); err != nil {
		t.Fatalf("failed to spawn winrm: %s", err)
	}
	defer conf.Shutdown()

	port := conf.listener.Addr().(*net.TCPAddr).Port
	url := fmt.Sprintf("http://127.0.0.1:%d/wsman", port)

	// 1. Initial probe (Expect 401)
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("failed to GET winrm: %s", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 2. Basic auth with SOAPAction
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer([]byte("<s:Envelope>...</s:Envelope>")))
	if err != nil {
		t.Fatalf("failed to create request: %s", err)
	}
	authVal := base64.StdEncoding.EncodeToString([]byte("winrmadmin:WinRMP@ssw0rd!"))
	req.Header.Set("Authorization", "Basic "+authVal)
	req.Header.Set("SOAPAction", "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Create")
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("failed to send basic auth: %s", err)
	}
	_ = resp.Body.Close()

	select {
	case rec := <-recordChan:
		if rec["_proto"] != "winrm" {
			t.Errorf("expected proto winrm, got %s", rec["_proto"])
		}
		if rec["username"] != "winrmadmin" || rec["password"] != "WinRMP@ssw0rd!" {
			t.Errorf("unexpected credentials: %v", rec)
		}
		if rec["soap_action"] != "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Create" {
			t.Errorf("unexpected soap_action: %s", rec["soap_action"])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for winrm credential")
	}
}

func TestKerberosCapture(t *testing.T) {
	recordChan := make(chan map[string]string, 10)
	rw := NewRecordWriter()
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		recordChan <- rec
		return nil
	})

	conf := NewConfKerberos()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw

	if err := SpawnKerberos(conf); err != nil {
		t.Fatalf("failed to spawn kerberos: %s", err)
	}
	defer conf.Shutdown()

	port := conf.tcpListener.Addr().(*net.TCPAddr).Port

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("failed to dial kerberos: %s", err)
	}
	defer conn.Close()

	// Construct minimal AS-REQ DER packet
	// [APPLICATION 10] (0x6a)
	var asReqBody bytes.Buffer
	// GeneralString username
	userStr := "svc_backup"
	asReqBody.WriteByte(0x1b)
	asReqBody.WriteByte(byte(len(userStr)))
	asReqBody.WriteString(userStr)

	// GeneralString realm
	realmStr := "EXAMPLE.COM"
	asReqBody.WriteByte(0x1b)
	asReqBody.WriteByte(byte(len(realmStr)))
	asReqBody.WriteString(realmStr)

	// PA-DATA SEQUENCE with PA-ENC-TIMESTAMP
	var paData bytes.Buffer
	paData.Write([]byte{0x02, 0x01, 0x02}) // INTEGER 2 (padata-type)
	// etype integer 23 (rc4-hmac)
	paData.Write([]byte{0x02, 0x01, 0x17})
	// cipher octet string (24 bytes)
	fakeCipher := bytes.Repeat([]byte{0x42}, 24)
	paData.WriteByte(0x04)
	paData.WriteByte(byte(len(fakeCipher)))
	paData.Write(fakeCipher)

	paSeq := paData.Bytes()
	asReqBody.WriteByte(0x30) // SEQUENCE
	asReqBody.WriteByte(byte(len(paSeq)))
	asReqBody.Write(paSeq)

	asReqBytes := asReqBody.Bytes()
	var packet bytes.Buffer
	packet.WriteByte(0x6a) // [APPLICATION 10]
	packet.WriteByte(byte(len(asReqBytes)))
	packet.Write(asReqBytes)

	// Prepend TCP 4-byte length
	var tcpMsg bytes.Buffer
	_ = binary.Write(&tcpMsg, binary.BigEndian, uint32(packet.Len()))
	tcpMsg.Write(packet.Bytes())

	if _, err := conn.Write(tcpMsg.Bytes()); err != nil {
		t.Fatalf("failed to send kerberos AS-REQ: %s", err)
	}

	// Read reply (KDC_ERR_PREAUTH_REQUIRED)
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatalf("failed to read kerberos reply header: %s", err)
	}
	respLen := binary.BigEndian.Uint32(header)
	respBody := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBody); err != nil {
		t.Fatalf("failed to read kerberos reply body: %s", err)
	}
	if respBody[0] != 0x7e { // [APPLICATION 30]
		t.Fatalf("expected KRB-ERROR [APPLICATION 30] (0x7e), got 0x%x", respBody[0])
	}

	select {
	case rec := <-recordChan:
		if rec["_proto"] != "kerberos" {
			t.Errorf("expected proto kerberos, got %s", rec["_proto"])
		}
		if rec["username"] != "svc_backup" || rec["realm"] != "EXAMPLE.COM" {
			t.Errorf("unexpected credentials: %v", rec)
		}
		if rec["etype"] != "23" {
			t.Errorf("expected etype 23, got %s", rec["etype"])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for kerberos credential")
	}
}
