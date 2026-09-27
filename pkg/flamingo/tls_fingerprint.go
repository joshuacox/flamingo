package flamingo

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TLSFingerprint contains JA3 and JA4 fingerprint strings
type TLSFingerprint struct {
	JA3       string
	JA3Raw    string
	JA4       string
	SNI       string
	Timestamp time.Time
}

// TLSFingerprintRegistry stores recent client TLS fingerprints keyed by remote address
type TLSFingerprintRegistry struct {
	mu           sync.RWMutex
	fingerprints map[string]TLSFingerprint
}

// GlobalTLSRegistry is the default singleton registry used across listeners
var GlobalTLSRegistry = NewTLSFingerprintRegistry()

// NewTLSFingerprintRegistry creates a new registry
func NewTLSFingerprintRegistry() *TLSFingerprintRegistry {
	reg := &TLSFingerprintRegistry{
		fingerprints: make(map[string]TLSFingerprint),
	}
	go reg.cleanupLoop()
	return reg
}

func (r *TLSFingerprintRegistry) cleanupLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		r.mu.Lock()
		cutoff := time.Now().Add(-5 * time.Minute)
		for k, v := range r.fingerprints {
			if v.Timestamp.Before(cutoff) {
				delete(r.fingerprints, k)
			}
		}
		r.mu.Unlock()
	}
}

// RecordClientHello computes and stores JA3 and JA4 fingerprints for a ClientHello
func (r *TLSFingerprintRegistry) RecordClientHello(addr string, chi *tls.ClientHelloInfo) TLSFingerprint {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	fp := ComputeTLSFingerprints(chi)

	r.mu.Lock()
	r.fingerprints[addr] = fp
	r.fingerprints[host] = fp
	r.mu.Unlock()

	return fp
}

// GetFingerprint retrieves fingerprint for a given address (host:port or host)
func (r *TLSFingerprintRegistry) GetFingerprint(addr string) (TLSFingerprint, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if fp, ok := r.fingerprints[addr]; ok {
		return fp, true
	}
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		if fp, ok := r.fingerprints[host]; ok {
			return fp, true
		}
	}
	return TLSFingerprint{}, false
}

// WrapTLSConfig configures GetConfigForClient to automatically record JA3/JA4 fingerprints
func (r *TLSFingerprintRegistry) WrapTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		cfg = &tls.Config{}
	}
	origGetConfig := cfg.GetConfigForClient

	cfg.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		if chi.Conn != nil {
			r.RecordClientHello(chi.Conn.RemoteAddr().String(), chi)
		}
		if origGetConfig != nil {
			return origGetConfig(chi)
		}
		return nil, nil
	}

	return cfg
}

// ComputeTLSFingerprints calculates JA3 and JA4 from ClientHelloInfo
func ComputeTLSFingerprints(chi *tls.ClientHelloInfo) TLSFingerprint {
	// 1. Compute JA3
	// JA3 format: SSLVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
	// Grease values to exclude: 0x0a0a, 0x1a1a, 0x2a2a, ..., 0xfafa
	isGrease := func(val uint16) bool {
		return (val&0x0f0f) == 0x0a0a && (val>>8) == (val&0xff)
	}

	// SSL Version
	sslVersion := uint16(0x0303) // default TLS 1.2
	if len(chi.SupportedVersions) > 0 {
		for _, v := range chi.SupportedVersions {
			if !isGrease(v) && v > sslVersion {
				sslVersion = v
			}
		}
	}

	// Ciphers
	var ciphers []string
	var rawCiphers []uint16
	for _, c := range chi.CipherSuites {
		if !isGrease(c) {
			ciphers = append(ciphers, strconv.Itoa(int(c)))
			rawCiphers = append(rawCiphers, c)
		}
	}

	// Curves
	var curves []string
	for _, curve := range chi.SupportedCurves {
		cVal := uint16(curve)
		if !isGrease(cVal) {
			curves = append(curves, strconv.Itoa(int(cVal)))
		}
	}

	// Point Formats
	var points []string
	for _, p := range chi.SupportedPoints {
		points = append(points, strconv.Itoa(int(p)))
	}

	// Extensions: Go's tls.ClientHelloInfo doesn't expose raw extension IDs directly,
	// but provides properties from which standard extensions are inferred if present:
	// ServerName (0), SupportedCurves (10), SupportedPoints (11), SignatureAlgorithms (13),
	// ALPN (16), SupportedVersions (43).
	var extList []uint16
	if chi.ServerName != "" {
		extList = append(extList, 0) // server_name
	}
	if len(chi.SupportedCurves) > 0 {
		extList = append(extList, 10) // supported_groups
	}
	if len(chi.SupportedPoints) > 0 {
		extList = append(extList, 11) // ec_point_formats
	}
	if len(chi.SignatureSchemes) > 0 {
		extList = append(extList, 13) // signature_algorithms
	}
	if len(chi.SupportedProtos) > 0 {
		extList = append(extList, 16) // ALPN
	}
	if len(chi.SupportedVersions) > 0 {
		extList = append(extList, 43) // supported_versions
	}

	var extStrs []string
	for _, e := range extList {
		extStrs = append(extStrs, strconv.Itoa(int(e)))
	}

	ja3Raw := fmt.Sprintf("%d,%s,%s,%s,%s",
		sslVersion,
		strings.Join(ciphers, "-"),
		strings.Join(extStrs, "-"),
		strings.Join(curves, "-"),
		strings.Join(points, "-"),
	)

	md5Hash := md5.Sum([]byte(ja3Raw))
	ja3Hash := hex.EncodeToString(md5Hash[:])

	// 2. Compute JA4
	// JA4 format: a_b_c
	// 'a': 4-character string:
	//   1: Protocol ('t' = TCP)
	//   2-3: TLS Version ('13' = TLS 1.3, '12' = TLS 1.2, '11', '10', 's3' = SSL 3.0, '00' = unknown)
	//   4: SNI indicator ('d' if domain, 'i' if IP, '0' if no SNI)
	//   5-6: 2-digit number of cipher suites (excluding grease)
	//   7-8: 2-digit number of extensions (excluding grease)
	//   9-10: First and last alphanumeric char of first ALPN or "00"
	protoChar := "t"
	var verStr string
	switch sslVersion {
	case 0x0304:
		verStr = "13"
	case 0x0303:
		verStr = "12"
	case 0x0302:
		verStr = "11"
	case 0x0301:
		verStr = "10"
	case 0x0300:
		verStr = "s3"
	default:
		verStr = "00"
	}

	sniChar := "0"
	if chi.ServerName != "" {
		if net.ParseIP(chi.ServerName) != nil {
			sniChar = "i"
		} else {
			sniChar = "d"
		}
	}

	numCiphers := len(ciphers)
	if numCiphers > 99 {
		numCiphers = 99
	}
	numExts := len(extList)
	if numExts > 99 {
		numExts = 99
	}

	alpnStr := "00"
	if len(chi.SupportedProtos) > 0 && len(chi.SupportedProtos[0]) > 0 {
		firstProto := chi.SupportedProtos[0]
		firstChar := firstProto[0]
		lastChar := firstProto[len(firstProto)-1]
		alpnStr = string([]byte{firstChar, lastChar})
	}

	partA := fmt.Sprintf("%s%s%s%02d%02d%s", protoChar, verStr, sniChar, numCiphers, numExts, alpnStr)

	// 'b': Truncated SHA256 (12 hex chars) of sorted ciphers
	sort.Slice(rawCiphers, func(i, j int) bool { return rawCiphers[i] < rawCiphers[j] })
	var sortedCipherHex []string
	for _, c := range rawCiphers {
		sortedCipherHex = append(sortedCipherHex, fmt.Sprintf("%04x", c))
	}
	cipherHash := sha256.Sum256([]byte(strings.Join(sortedCipherHex, ",")))
	partB := hex.EncodeToString(cipherHash[:])[:12]

	// 'c': Truncated SHA256 (12 hex chars) of sorted extensions
	sort.Slice(extList, func(i, j int) bool { return extList[i] < extList[j] })
	var sortedExtHex []string
	for _, e := range extList {
		sortedExtHex = append(sortedExtHex, fmt.Sprintf("%04x", e))
	}
	extHash := sha256.Sum256([]byte(strings.Join(sortedExtHex, ",")))
	partC := hex.EncodeToString(extHash[:])[:12]

	ja4 := fmt.Sprintf("%s_%s_%s", partA, partB, partC)

	return TLSFingerprint{
		JA3:       ja3Hash,
		JA3Raw:    ja3Raw,
		JA4:       ja4,
		SNI:       chi.ServerName,
		Timestamp: time.Now(),
	}
}
