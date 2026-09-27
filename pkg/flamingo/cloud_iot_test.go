package flamingo

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDockerCapture(t *testing.T) {
	recordChan := make(chan map[string]string, 10)
	rw := NewRecordWriter()
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		recordChan <- rec
		return nil
	})

	conf := NewConfDocker()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw

	if err := SpawnDocker(conf); err != nil {
		t.Fatalf("failed to spawn docker: %v", err)
	}
	defer conf.Shutdown()

	client := &http.Client{Timeout: 5 * time.Second}
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", conf.BindPort)

	// Test 1: Ping endpoint
	resp, err := client.Get(baseURL + "/_ping")
	if err != nil {
		t.Fatalf("failed to get /_ping: %v", err)
	}
	defer resp.Body.Close()
	pingBody, _ := io.ReadAll(resp.Body)
	if string(pingBody) != "OK" {
		t.Fatalf("expected 'OK', got %q", string(pingBody))
	}

	// Read record for ping
	select {
	case rec := <-recordChan:
		if rec["_proto"] != "docker" {
			t.Fatalf("expected _proto docker, got %s", rec["_proto"])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for docker ping record")
	}

	// Test 2: Container creation with basic auth
	createReq := map[string]interface{}{
		"Image": "xmrig/xmrig:latest",
		"Cmd":   []string{"-o", "pool.minexmr.com:4444"},
	}
	reqData, _ := json.Marshal(createReq)
	req, err := http.NewRequest(http.MethodPost, baseURL+"/v1.43/containers/create", bytes.NewReader(reqData))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("docker_admin", "SuperSecretDockerPass123!")

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("failed to post containers/create: %v", err)
	}
	defer resp.Body.Close()

	select {
	case rec := <-recordChan:
		if rec["username"] != "docker_admin" {
			t.Fatalf("expected username 'docker_admin', got %q", rec["username"])
		}
		if rec["password"] != "SuperSecretDockerPass123!" {
			t.Fatalf("expected password 'SuperSecretDockerPass123!', got %q", rec["password"])
		}
		if rec["image"] != "xmrig/xmrig:latest" {
			t.Fatalf("expected image 'xmrig/xmrig:latest', got %q", rec["image"])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for docker container create record")
	}
}

func TestKubeletCapture(t *testing.T) {
	recordChan := make(chan map[string]string, 10)
	rw := NewRecordWriter()
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		recordChan <- rec
		return nil
	})

	conf := NewConfKubelet()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.TLS = false // Test with plain HTTP
	conf.RecordWriter = rw

	if err := SpawnKubelet(conf); err != nil {
		t.Fatalf("failed to spawn kubelet: %v", err)
	}
	defer conf.Shutdown()

	client := &http.Client{Timeout: 5 * time.Second}
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", conf.BindPort)

	// Create synthetic K8s service account JWT
	jwtClaims := `{"iss":"kubernetes/serviceaccount","kubernetes.io/serviceaccount/namespace":"prod-apps","kubernetes.io/serviceaccount/service-account.name":"vault-auth","sub":"system:serviceaccount:prod-apps:vault-auth"}`
	b64Header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	b64Claims := base64.RawURLEncoding.EncodeToString([]byte(jwtClaims))
	fakeJWT := fmt.Sprintf("%s.%s.fakesignaturehere", b64Header, b64Claims)

	req, err := http.NewRequest(http.MethodGet, baseURL+"/pods", nil)
	if err != nil {
		t.Fatalf("failed to create req: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+fakeJWT)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to query /pods: %v", err)
	}
	defer resp.Body.Close()

	select {
	case rec := <-recordChan:
		if rec["_proto"] != "kubelet" {
			t.Fatalf("expected _proto kubelet, got %s", rec["_proto"])
		}
		if rec["service_account"] != "vault-auth" {
			t.Fatalf("expected service_account vault-auth, got %q", rec["service_account"])
		}
		if rec["namespace"] != "prod-apps" {
			t.Fatalf("expected namespace prod-apps, got %q", rec["namespace"])
		}
		if rec["jwt_sub"] != "system:serviceaccount:prod-apps:vault-auth" {
			t.Fatalf("expected jwt_sub, got %q", rec["jwt_sub"])
		}
		if rec["password"] != fakeJWT {
			t.Fatalf("expected token stored in password, got %q", rec["password"])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for kubelet record")
	}
}

func TestEtcdCapture(t *testing.T) {
	recordChan := make(chan map[string]string, 10)
	rw := NewRecordWriter()
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		recordChan <- rec
		return nil
	})

	conf := NewConfEtcd()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw

	if err := SpawnEtcd(conf); err != nil {
		t.Fatalf("failed to spawn etcd: %v", err)
	}
	defer conf.Shutdown()

	client := &http.Client{Timeout: 5 * time.Second}
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", conf.BindPort)

	authBody := []byte(`{"name":"etcd-admin","password":"ClusterMasterKey99!"}`)
	resp, err := client.Post(baseURL+"/v3/auth/authenticate", "application/json", bytes.NewReader(authBody))
	if err != nil {
		t.Fatalf("failed to post auth to etcd: %v", err)
	}
	defer resp.Body.Close()

	select {
	case rec := <-recordChan:
		if rec["_proto"] != "etcd" {
			t.Fatalf("expected _proto etcd, got %s", rec["_proto"])
		}
		if rec["username"] != "etcd-admin" {
			t.Fatalf("expected username etcd-admin, got %q", rec["username"])
		}
		if rec["password"] != "ClusterMasterKey99!" {
			t.Fatalf("expected password ClusterMasterKey99!, got %q", rec["password"])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for etcd record")
	}
}

func TestVNCCapture(t *testing.T) {
	recordChan := make(chan map[string]string, 10)
	rw := NewRecordWriter()
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		recordChan <- rec
		return nil
	})

	conf := NewConfVNC()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw

	if err := SpawnVNC(conf); err != nil {
		t.Fatalf("failed to spawn VNC: %v", err)
	}
	defer conf.Shutdown()

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", conf.BindPort))
	if err != nil {
		t.Fatalf("failed to connect to VNC: %v", err)
	}
	defer conn.Close()

	// 1. Read Server Version (12 bytes)
	ver := make([]byte, 12)
	if _, err := io.ReadFull(conn, ver); err != nil {
		t.Fatalf("failed to read vnc server version: %v", err)
	}
	if string(ver) != "RFB 003.008\n" {
		t.Fatalf("unexpected vnc server version: %q", string(ver))
	}

	// 2. Send Client Version (12 bytes)
	if _, err := conn.Write([]byte("RFB 003.008\n")); err != nil {
		t.Fatalf("failed to send client version: %v", err)
	}

	// 3. Read Security Types (1 byte count + types)
	secTypes := make([]byte, 2)
	if _, err := io.ReadFull(conn, secTypes); err != nil {
		t.Fatalf("failed to read security types: %v", err)
	}
	if secTypes[0] != 1 || secTypes[1] != 2 {
		t.Fatalf("unexpected security types: %v", secTypes)
	}

	// 4. Send Selected Security Type (1 byte: 2)
	if _, err := conn.Write([]byte{2}); err != nil {
		t.Fatalf("failed to send selected security type: %v", err)
	}

	// 5. Read 16-byte Challenge
	challenge := make([]byte, 16)
	if _, err := io.ReadFull(conn, challenge); err != nil {
		t.Fatalf("failed to read challenge: %v", err)
	}

	// 6. Send 16-byte Response
	response := bytes.Repeat([]byte{0x42}, 16)
	if _, err := conn.Write(response); err != nil {
		t.Fatalf("failed to send response: %v", err)
	}

	// 7. Read SecurityResult (uint32 1 = Failure)
	var secResult uint32
	if err := binary.Read(conn, binary.BigEndian, &secResult); err != nil {
		t.Fatalf("failed to read security result: %v", err)
	}
	if secResult != 1 {
		t.Fatalf("expected security result 1 (failure), got %d", secResult)
	}

	select {
	case rec := <-recordChan:
		if rec["_proto"] != "vnc" {
			t.Fatalf("expected _proto vnc, got %s", rec["_proto"])
		}
		expectedChallenge := hex.EncodeToString(challenge)
		if rec["challenge"] != expectedChallenge {
			t.Fatalf("expected challenge %s, got %s", expectedChallenge, rec["challenge"])
		}
		expectedResponse := hex.EncodeToString(response)
		if rec["response"] != expectedResponse {
			t.Fatalf("expected response %s, got %s", expectedResponse, rec["response"])
		}
		if !strings.HasPrefix(rec["password"], "$vnc$*") {
			t.Fatalf("expected $vnc$* prefix in password, got %s", rec["password"])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for VNC record")
	}
}

func TestMQTTCapture(t *testing.T) {
	recordChan := make(chan map[string]string, 10)
	rw := NewRecordWriter()
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		recordChan <- rec
		return nil
	})

	conf := NewConfMQTT()
	conf.BindHost = "127.0.0.1"
	conf.BindPort = 0
	conf.RecordWriter = rw

	if err := SpawnMQTT(conf); err != nil {
		t.Fatalf("failed to spawn MQTT: %v", err)
	}
	defer conf.Shutdown()

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", conf.BindPort))
	if err != nil {
		t.Fatalf("failed to connect to MQTT: %v", err)
	}
	defer conn.Close()

	// Construct synthetic MQTT 3.1.1 CONNECT packet
	// Variable header:
	var varHeader bytes.Buffer
	// Protocol Name: "MQTT"
	_ = binary.Write(&varHeader, binary.BigEndian, uint16(4))
	varHeader.WriteString("MQTT")
	// Protocol Level: 4 (v3.1.1)
	varHeader.WriteByte(4)
	// Connect Flags: Username (0x80) | Password (0x40) | Clean Session (0x02) = 0xC2
	varHeader.WriteByte(0xC2)
	// Keep Alive: 60s
	_ = binary.Write(&varHeader, binary.BigEndian, uint16(60))

	// Payload:
	var payload bytes.Buffer
	// Client ID: "iot-sensor-node"
	_ = binary.Write(&payload, binary.BigEndian, uint16(len("iot-sensor-node")))
	payload.WriteString("iot-sensor-node")
	// Username: "sensor_user"
	_ = binary.Write(&payload, binary.BigEndian, uint16(len("sensor_user")))
	payload.WriteString("sensor_user")
	// Password: "MqttPassword789!"
	_ = binary.Write(&payload, binary.BigEndian, uint16(len("MqttPassword789!")))
	payload.WriteString("MqttPassword789!")

	body := append(varHeader.Bytes(), payload.Bytes()...)

	// Fixed header:
	var pkt bytes.Buffer
	pkt.WriteByte(0x10) // CONNECT
	pkt.WriteByte(byte(len(body)))
	pkt.Write(body)

	if _, err := conn.Write(pkt.Bytes()); err != nil {
		t.Fatalf("failed to write MQTT CONNECT: %v", err)
	}

	// Read CONNACK: 4 bytes (0x20, 0x02, 0x00, 0x04)
	connack := make([]byte, 4)
	if _, err := io.ReadFull(conn, connack); err != nil {
		t.Fatalf("failed to read CONNACK: %v", err)
	}
	if connack[0] != 0x20 || connack[3] != 0x04 {
		t.Fatalf("unexpected CONNACK bytes: %v", connack)
	}

	select {
	case rec := <-recordChan:
		if rec["_proto"] != "mqtt" {
			t.Fatalf("expected _proto mqtt, got %s", rec["_proto"])
		}
		if rec["client_id"] != "iot-sensor-node" {
			t.Fatalf("expected client_id 'iot-sensor-node', got %q", rec["client_id"])
		}
		if rec["username"] != "sensor_user" {
			t.Fatalf("expected username 'sensor_user', got %q", rec["username"])
		}
		if rec["password"] != "MqttPassword789!" {
			t.Fatalf("expected password 'MqttPassword789!', got %q", rec["password"])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for MQTT record")
	}
}
