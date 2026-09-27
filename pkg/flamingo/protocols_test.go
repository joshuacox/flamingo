package flamingo

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestPOP3Capture(t *testing.T) {
	recordChan := make(chan map[string]string, 10)
	rw := NewRecordWriter()
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		recordChan <- rec
		return nil
	})

	conf := NewConfPOP3()
	conf.BindPort = 0
	conf.BindHost = "127.0.0.1"
	conf.RecordWriter = rw

	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("failed to gen cert: %s", err)
	}
	conf.TLSCert = certPEM
	conf.TLSKey = keyPEM
	conf.TLSName = "localhost"

	if err := SpawnPOP3(conf); err != nil {
		t.Fatalf("failed to spawn POP3: %s", err)
	}
	defer conf.Shutdown()

	port := conf.listener.Addr().(*net.TCPAddr).Port

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial: %s", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	banner, _ := reader.ReadString('\n')
	if !strings.HasPrefix(banner, "+OK") {
		t.Fatalf("unexpected banner: %s", banner)
	}

	// USER / PASS
	fmt.Fprintf(conn, "USER popuser\r\n")
	uResp, _ := reader.ReadString('\n')
	if !strings.HasPrefix(uResp, "+OK") {
		t.Fatalf("expected +OK, got %s", uResp)
	}

	fmt.Fprintf(conn, "PASS poppass\r\n")
	pResp, _ := reader.ReadString('\n')
	if !strings.HasPrefix(pResp, "-ERR") {
		t.Fatalf("expected -ERR, got %s", pResp)
	}

	select {
	case rec := <-recordChan:
		if rec["username"] != "popuser" || rec["password"] != "poppass" {
			t.Fatalf("mismatched record: %v", rec)
		}
		if rec["_proto"] != "pop3" {
			t.Fatalf("expected proto pop3, got %s", rec["_proto"])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for POP3 credential")
	}
}

func TestSMTPCapture(t *testing.T) {
	recordChan := make(chan map[string]string, 10)
	rw := NewRecordWriter()
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		recordChan <- rec
		return nil
	})

	conf := NewConfSMTP()
	conf.BindPort = 0
	conf.BindHost = "127.0.0.1"
	conf.RecordWriter = rw

	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("failed to gen cert: %s", err)
	}
	conf.TLSCert = certPEM
	conf.TLSKey = keyPEM
	conf.TLSName = "localhost"

	if err := SpawnSMTP(conf); err != nil {
		t.Fatalf("failed to spawn SMTP: %s", err)
	}
	defer conf.Shutdown()

	port := conf.listener.Addr().(*net.TCPAddr).Port

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial: %s", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	banner, _ := reader.ReadString('\n')
	if !strings.HasPrefix(banner, "220") {
		t.Fatalf("unexpected banner: %s", banner)
	}

	fmt.Fprintf(conn, "EHLO test.local\r\n")
	for {
		line, _ := reader.ReadString('\n')
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}

	fmt.Fprintf(conn, "MAIL FROM:<sender@test.com>\r\n")
	_, _ = reader.ReadString('\n')

	fmt.Fprintf(conn, "RCPT TO:<victim@test.com>\r\n")
	_, _ = reader.ReadString('\n')

	// AUTH LOGIN
	fmt.Fprintf(conn, "AUTH LOGIN\r\n")
	c1, _ := reader.ReadString('\n')
	if !strings.HasPrefix(c1, "334") {
		// 334 or challenge prompt
	}
	// Username: in base64 = c210cHVzZXI= (smtpuser)
	fmt.Fprintf(conn, "c210cHVzZXI=\r\n")
	_, _ = reader.ReadString('\n')

	// Password: in base64 = c210cHBhc3M= (smtppass)
	fmt.Fprintf(conn, "c210cHBhc3M=\r\n")
	_, _ = reader.ReadString('\n')

	select {
	case rec := <-recordChan:
		if rec["username"] != "smtpuser" || rec["password"] != "smtppass" {
			t.Fatalf("mismatched record: %v", rec)
		}
		if rec["_proto"] != "smtp" {
			t.Fatalf("expected proto smtp, got %s", rec["_proto"])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for SMTP credential")
	}
}

func TestRedisCapture(t *testing.T) {
	recordChan := make(chan map[string]string, 10)
	rw := NewRecordWriter()
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		recordChan <- rec
		return nil
	})

	conf := NewConfRedis()
	conf.BindPort = 0
	conf.BindHost = "127.0.0.1"
	conf.RecordWriter = rw

	if err := SpawnRedis(conf); err != nil {
		t.Fatalf("failed to spawn Redis: %s", err)
	}
	defer conf.Shutdown()

	port := conf.listener.Addr().(*net.TCPAddr).Port

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial: %s", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Send Redis 6 ACL: AUTH myuser mypass
	fmt.Fprintf(conn, "*3\r\n$4\r\nAUTH\r\n$6\r\nmyuser\r\n$6\r\nmypass\r\n")
	resp, _ := reader.ReadString('\n')
	if !strings.HasPrefix(resp, "-WRONGPASS") {
		t.Fatalf("expected -WRONGPASS, got: %s", resp)
	}

	select {
	case rec := <-recordChan:
		if rec["username"] != "myuser" || rec["password"] != "mypass" {
			t.Fatalf("mismatched record: %v", rec)
		}
		if rec["_proto"] != "redis" {
			t.Fatalf("expected proto redis, got %s", rec["_proto"])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for Redis credential")
	}
}

func TestTelnetCapture(t *testing.T) {
	recordChan := make(chan map[string]string, 10)
	rw := NewRecordWriter()
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		recordChan <- rec
		return nil
	})

	conf := NewConfTelnet()
	conf.BindPort = 0
	conf.BindHost = "127.0.0.1"
	conf.RecordWriter = rw

	if err := SpawnTelnet(conf); err != nil {
		t.Fatalf("failed to spawn Telnet: %s", err)
	}
	defer conf.Shutdown()

	port := conf.listener.Addr().(*net.TCPAddr).Port

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial: %s", err)
	}
	defer conn.Close()

	// Wait for login: prompt
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if !strings.Contains(string(buf[:n]), "login:") {
		// keep reading till login:
	}

	fmt.Fprintf(conn, "telnetuser\r\n")
	n, _ = conn.Read(buf)

	fmt.Fprintf(conn, "telnetpass\r\n")
	_, _ = conn.Read(buf)

	select {
	case rec := <-recordChan:
		if rec["username"] != "telnetuser" || rec["password"] != "telnetpass" {
			t.Fatalf("mismatched record: %v", rec)
		}
		if rec["_proto"] != "telnet" {
			t.Fatalf("expected proto telnet, got %s", rec["_proto"])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for Telnet credential")
	}
}
