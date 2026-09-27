package flamingo

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/atredispartners/flamingo/pkg/ldap"
)

func TestLDAPCapture(t *testing.T) {
	recordChan := make(chan map[string]string, 10)
	rw := NewRecordWriter()
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		recordChan <- rec
		return nil
	})

	conf := NewConfLDAP()
	conf.BindPort = 0
	conf.BindHost = "127.0.0.1"
	conf.RecordWriter = rw

	if err := SpawnLDAP(conf); err != nil {
		t.Fatalf("failed to spawn LDAP: %s", err)
	}
	defer conf.Shutdown()

	port := conf.listener.Addr().(*net.TCPAddr).Port

	l, err := ldap.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("failed to dial LDAP: %s", err)
	}
	defer l.Close()

	// Perform Bind with username and password
	_ = l.Bind("admin@domain.local", "Hunter2!")

	select {
	case rec := <-recordChan:
		if rec["username"] != "admin@domain.local" || rec["password"] != "Hunter2!" {
			t.Fatalf("mismatched LDAP credential: %v", rec)
		}
		if rec["_proto"] != "ldap" {
			t.Fatalf("expected proto ldap, got %s", rec["_proto"])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for LDAP credential")
	}
}
