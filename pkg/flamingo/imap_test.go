package flamingo

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func setupTestIMAPServer(t *testing.T, isTLS bool) (*ConfIMAP, uint16, <-chan map[string]string) {
	recordChan := make(chan map[string]string, 10)
	rw := NewRecordWriter()
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		recordChan <- rec
		return nil
	})

	conf := NewConfIMAP()
	conf.BindPort = 0 // OS assigned port
	conf.BindHost = "127.0.0.1"
	conf.RecordWriter = rw
	conf.TLS = isTLS

	certPEM, keyPEM, err := generateTestCertAndKey()
	if err != nil {
		t.Fatalf("failed to generate test cert: %s", err)
	}
	conf.TLSCert = certPEM
	conf.TLSKey = keyPEM
	conf.TLSName = "localhost"

	err = SpawnIMAP(conf)
	if err != nil {
		t.Fatalf("failed to spawn IMAP: %s", err)
	}

	tcpAddr, ok := conf.listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener is not a TCPAddr")
	}

	return conf, uint16(tcpAddr.Port), recordChan
}

func generateTestCertAndKey() (string, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Flamingo Test"},
			CommonName:   "localhost",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}

	var certBuf bytes.Buffer
	if err := pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return "", "", err
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", err
	}

	var keyBuf bytes.Buffer
	if err := pem.Encode(&keyBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return "", "", err
	}

	return certBuf.String(), keyBuf.String(), nil
}

func TestIMAPLogin(t *testing.T) {
	conf, port, recordChan := setupTestIMAPServer(t, false)
	defer conf.Shutdown()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect: %s", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read greeting: %s", err)
	}
	if !strings.Contains(greeting, "* OK") {
		t.Fatalf("expected greeting, got: %s", greeting)
	}

	// Send LOGIN with double quoted password
	fmt.Fprintf(conn, "A001 LOGIN testuser \"supersecretpassword\"\r\n")

	resp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read response: %s", err)
	}
	if !strings.Contains(resp, "A001 NO") {
		t.Fatalf("expected A001 NO, got: %s", resp)
	}

	// Check if captured
	select {
	case rec := <-recordChan:
		if rec["username"] != "testuser" || rec["password"] != "supersecretpassword" {
			t.Fatalf("mismatched captured credentials: %v", rec)
		}
		if rec["_proto"] != "imap" {
			t.Fatalf("expected proto imap, got %s", rec["_proto"])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for credential record")
	}
}

func TestIMAPAuthPlain(t *testing.T) {
	conf, port, recordChan := setupTestIMAPServer(t, false)
	defer conf.Shutdown()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect: %s", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	_, _ = reader.ReadString('\n') // Greeting

	// Send AUTHENTICATE PLAIN with continuation
	fmt.Fprintf(conn, "A002 AUTHENTICATE PLAIN\r\n")

	resp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read response: %s", err)
	}
	if !strings.HasPrefix(resp, "+") {
		t.Fatalf("expected continuation +, got: %s", resp)
	}

	// Payload is base64("\0plainuser\0plainpass")
	payload := base64.StdEncoding.EncodeToString([]byte("\x00plainuser\x00plainpass"))
	fmt.Fprintf(conn, "%s\r\n", payload)

	resp, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read auth response: %s", err)
	}
	if !strings.Contains(resp, "A002 NO") {
		t.Fatalf("expected NO, got: %s", resp)
	}

	select {
	case rec := <-recordChan:
		if rec["username"] != "plainuser" || rec["password"] != "plainpass" {
			t.Fatalf("mismatched captured credentials: %v", rec)
		}
		if rec["method"] != "auth_plain" {
			t.Fatalf("expected method auth_plain, got %s", rec["method"])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for credential record")
	}
}

func TestIMAPAuthLogin(t *testing.T) {
	conf, port, recordChan := setupTestIMAPServer(t, false)
	defer conf.Shutdown()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect: %s", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	_, _ = reader.ReadString('\n') // Greeting

	fmt.Fprintf(conn, "A003 AUTHENTICATE LOGIN\r\n")

	// Challenge 1
	c1, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(c1, "+") {
		t.Fatalf("expected +, got: %s", c1)
	}

	// Send username
	uB64 := base64.StdEncoding.EncodeToString([]byte("loginuser"))
	fmt.Fprintf(conn, "%s\r\n", uB64)

	// Challenge 2
	c2, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(c2, "+") {
		t.Fatalf("expected +, got: %s", c2)
	}

	// Send password
	pB64 := base64.StdEncoding.EncodeToString([]byte("loginpass"))
	fmt.Fprintf(conn, "%s\r\n", pB64)

	resp, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(resp, "A003 NO") {
		t.Fatalf("expected NO, got: %s", resp)
	}

	select {
	case rec := <-recordChan:
		if rec["username"] != "loginuser" || rec["password"] != "loginpass" {
			t.Fatalf("mismatched captured credentials: %v", rec)
		}
		if rec["method"] != "auth_login" {
			t.Fatalf("expected method auth_login, got %s", rec["method"])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for credential record")
	}
}

func TestIMAPStartTLS(t *testing.T) {
	conf, port, recordChan := setupTestIMAPServer(t, false)
	defer conf.Shutdown()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect: %s", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	_, _ = reader.ReadString('\n') // Greeting

	// Send STARTTLS
	fmt.Fprintf(conn, "A004 STARTTLS\r\n")

	resp, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(resp, "A004 OK") {
		t.Fatalf("expected STARTTLS OK, got: %s", resp)
	}

	// Upgrade client side to TLS
	tlsClient := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("tls handshake failed: %s", err)
	}

	tlsReader := bufio.NewReader(tlsClient)

	// Send LOGIN over TLS
	fmt.Fprintf(tlsClient, "A005 LOGIN tlsuser tlspass\r\n")

	loginResp, err := tlsReader.ReadString('\n')
	if err != nil || !strings.Contains(loginResp, "A005 NO") {
		t.Fatalf("expected login response over TLS, got: %s", loginResp)
	}

	select {
	case rec := <-recordChan:
		if rec["username"] != "tlsuser" || rec["password"] != "tlspass" {
			t.Fatalf("mismatched credentials: %v", rec)
		}
		if rec["_proto"] != "imaps" {
			t.Fatalf("expected proto imaps, got %s", rec["_proto"])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for credential record")
	}
}
