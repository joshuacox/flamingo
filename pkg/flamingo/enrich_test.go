package flamingo

import (
	"crypto/tls"
	"strings"
	"testing"
	"time"
)

func TestTLSFingerprinting(t *testing.T) {
	chi := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{0x0303, 0x0304}, // TLS 1.2, TLS 1.3
		CipherSuites: []uint16{
			0x1301, 0x1302, 0x1303, // TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
			0xc02b, 0xc02f, 0xc02c, // ECDHE-ECDSA/RSA
		},
		ServerName:       "honeypot.local",
		SupportedCurves:  []tls.CurveID{tls.X25519, tls.CurveP256},
		SupportedPoints:  []uint8{0}, // uncompressed
		SupportedProtos:  []string{"h2", "http/1.1"},
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256},
	}

	fp := ComputeTLSFingerprints(chi)

	if len(fp.JA3) != 32 {
		t.Fatalf("expected 32-char hex JA3 hash, got %d (%s)", len(fp.JA3), fp.JA3)
	}
	if !strings.HasPrefix(fp.JA4, "t13d") {
		t.Fatalf("expected JA4 to start with t13d (TCP, TLS 1.3, domain SNI), got %s", fp.JA4)
	}
	parts := strings.Split(fp.JA4, "_")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts in JA4, got %d (%s)", len(parts), fp.JA4)
	}
	if len(parts[1]) != 12 || len(parts[2]) != 12 {
		t.Fatalf("expected 12-char hashes in JA4 parts b and c, got %s and %s", parts[1], parts[2])
	}

	// Test Registry
	reg := NewTLSFingerprintRegistry()
	reg.RecordClientHello("192.168.1.50:54321", chi)

	cachedFP, ok := reg.GetFingerprint("192.168.1.50:54321")
	if !ok {
		t.Fatalf("expected to find fingerprint in registry")
	}
	if cachedFP.JA3 != fp.JA3 || cachedFP.JA4 != fp.JA4 {
		t.Fatalf("cached fingerprint does not match computed")
	}
}

func TestThreatEnrichment(t *testing.T) {
	reg := NewTLSFingerprintRegistry()
	enricher, err := NewEnricher(EnricherConfig{}, reg)
	if err != nil {
		t.Fatalf("failed to initialize enricher: %v", err)
	}
	defer enricher.Close()

	enricher.AddTorIP("185.220.101.5")
	_ = enricher.AddScannerCIDR("198.20.69.0/24", "shodan")
	_ = enricher.AddScannerCIDR("162.142.125.0/24", "censys")

	// Case 1: Local / Loopback IP
	recLocal := map[string]string{"_host": "127.0.0.1:8080"}
	enricher.Enrich(recLocal)
	if recLocal["_is_local"] != "true" {
		t.Fatalf("expected _is_local to be true for 127.0.0.1, got %s", recLocal["_is_local"])
	}

	// Case 2: Tor exit node
	recTor := map[string]string{"_host": "185.220.101.5:445"}
	enricher.Enrich(recTor)
	if recTor["_is_tor"] != "true" {
		t.Fatalf("expected _is_tor to be true, got %s", recTor["_is_tor"])
	}

	// Case 3: Known Scanner (Shodan)
	recShodan := map[string]string{"_host": "198.20.69.42:22"}
	enricher.Enrich(recShodan)
	if recShodan["_scanner"] != "shodan" {
		t.Fatalf("expected _scanner shodan, got %s", recShodan["_scanner"])
	}

	// Case 4: Known Scanner (Censys)
	recCensys := map[string]string{"_host": "162.142.125.10:443"}
	enricher.Enrich(recCensys)
	if recCensys["_scanner"] != "censys" {
		t.Fatalf("expected _scanner censys, got %s", recCensys["_scanner"])
	}
}

func TestRecordWriterEnrichmentIntegration(t *testing.T) {
	recordChan := make(chan map[string]string, 5)
	rw := NewRecordWriter()
	rw.OutputWriters = append(rw.OutputWriters, func(rec map[string]string) error {
		recordChan <- rec
		return nil
	})

	tlsReg := NewTLSFingerprintRegistry()
	chi := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{0x0303},
		CipherSuites:      []uint16{0xc02f, 0xc02b},
		ServerName:        "portal.company.com",
	}
	tlsReg.RecordClientHello("10.0.5.12:49812", chi)

	enricher, _ := NewEnricher(EnricherConfig{}, tlsReg)
	enricher.AddTorIP("10.0.5.12")
	rw.Enricher = enricher

	rw.Record("credential", "winrms", "10.0.5.12:49812", map[string]string{
		"username": "domain_admin",
		"password": "Password123!",
	})

	select {
	case rec := <-recordChan:
		if rec["_is_local"] != "true" {
			t.Fatalf("expected _is_local true for 10.0.5.12, got %s", rec["_is_local"])
		}
		if rec["_is_tor"] != "true" {
			t.Fatalf("expected _is_tor true, got %s", rec["_is_tor"])
		}
		if rec["_ja3"] == "" {
			t.Fatalf("expected _ja3 to be enriched")
		}
		if rec["_ja4"] == "" {
			t.Fatalf("expected _ja4 to be enriched")
		}
		if rec["_sni"] != "portal.company.com" {
			t.Fatalf("expected _sni portal.company.com, got %s", rec["_sni"])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for enriched record")
	}
}
