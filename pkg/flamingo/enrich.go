package flamingo

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
	log "github.com/sirupsen/logrus"
)

// ScannerRange associates a CIDR subnet with a scanner name (e.g. Shodan, Censys)
type ScannerRange struct {
	IPNet *net.IPNet
	Name  string
}

// EnricherConfig contains configuration options for threat intelligence and enrichment
type EnricherConfig struct {
	GeoIPCityDB string
	GeoIPASNDB  string
	EnableRDNS  bool
	TorList     string
	ScannerList string
}

// Enricher provides GeoIP, Reverse DNS, Threat Intel, and TLS fingerprint enrichment
type Enricher struct {
	cityDB      *geoip2.Reader
	asnDB       *geoip2.Reader
	enableRDNS  bool
	rdnsCache   sync.Map // ip -> string
	torIPs      map[string]struct{}
	scanners    []ScannerRange
	tlsRegistry *TLSFingerprintRegistry
	mu          sync.RWMutex
}

// NewEnricher initializes the enrichment engine
func NewEnricher(cfg EnricherConfig, tlsReg *TLSFingerprintRegistry) (*Enricher, error) {
	if tlsReg == nil {
		tlsReg = GlobalTLSRegistry
	}
	e := &Enricher{
		enableRDNS:  cfg.EnableRDNS,
		torIPs:      make(map[string]struct{}),
		tlsRegistry: tlsReg,
	}

	// 1. Load GeoIP City DB if provided
	if cfg.GeoIPCityDB != "" {
		db, err := geoip2.Open(cfg.GeoIPCityDB)
		if err != nil {
			log.Warnf("failed to open GeoIP city database %s: %v", cfg.GeoIPCityDB, err)
		} else {
			e.cityDB = db
			log.Infof("loaded GeoIP city database: %s", cfg.GeoIPCityDB)
		}
	}

	// 2. Load GeoIP ASN DB if provided
	if cfg.GeoIPASNDB != "" {
		db, err := geoip2.Open(cfg.GeoIPASNDB)
		if err != nil {
			log.Warnf("failed to open GeoIP ASN database %s: %v", cfg.GeoIPASNDB, err)
		} else {
			e.asnDB = db
			log.Infof("loaded GeoIP ASN database: %s", cfg.GeoIPASNDB)
		}
	}

	// 3. Initialize default scanner CIDR ranges
	e.loadDefaultScanners()

	// 4. Load custom scanner list if provided
	if cfg.ScannerList != "" {
		e.loadScannerFile(cfg.ScannerList)
	}

	// 5. Load Tor list if provided
	if cfg.TorList != "" {
		e.loadTorFile(cfg.TorList)
	}

	return e, nil
}

// Close cleanly releases any open database handles
func (e *Enricher) Close() {
	if e.cityDB != nil {
		_ = e.cityDB.Close()
	}
	if e.asnDB != nil {
		_ = e.asnDB.Close()
	}
}

// Enrich decorates a credential / event record with GeoIP, PTR, Threat tags, and TLS fingerprints
func (e *Enricher) Enrich(rec map[string]string) {
	hostStr := rec["_host"]
	if hostStr == "" {
		return
	}

	ipStr, _, err := net.SplitHostPort(hostStr)
	if err != nil {
		ipStr = hostStr
	}

	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		return
	}

	// 1. Local / Private IP detection
	if parsedIP.IsLoopback() || parsedIP.IsPrivate() || parsedIP.IsUnspecified() {
		rec["_is_local"] = "true"
	}

	// 2. GeoIP City lookup
	if e.cityDB != nil && !parsedIP.IsLoopback() && !parsedIP.IsPrivate() {
		city, err := e.cityDB.City(parsedIP)
		if err == nil && city != nil {
			if city.Country.IsoCode != "" {
				rec["_geo_country_code"] = city.Country.IsoCode
			}
			if countryName, ok := city.Country.Names["en"]; ok && countryName != "" {
				rec["_geo_country"] = countryName
			}
			if cityName, ok := city.City.Names["en"]; ok && cityName != "" {
				rec["_geo_city"] = cityName
			}
			if city.Location.Latitude != 0 || city.Location.Longitude != 0 {
				rec["_geo_lat"] = fmt.Sprintf("%.4f", city.Location.Latitude)
				rec["_geo_lon"] = fmt.Sprintf("%.4f", city.Location.Longitude)
			}
		}
	}

	// 3. GeoIP ASN lookup
	if e.asnDB != nil && !parsedIP.IsLoopback() && !parsedIP.IsPrivate() {
		asn, err := e.asnDB.ASN(parsedIP)
		if err == nil && asn != nil {
			if asn.AutonomousSystemNumber != 0 {
				rec["_asn_number"] = fmt.Sprintf("AS%d", asn.AutonomousSystemNumber)
			}
			if asn.AutonomousSystemOrganization != "" {
				rec["_asn_org"] = asn.AutonomousSystemOrganization
			}
		}
	}

	// 4. Reverse DNS (non-blocking with cache and 500ms timeout)
	if e.enableRDNS {
		if ptr, ok := e.resolvePTR(ipStr); ok && ptr != "" {
			rec["_client_ptr"] = ptr
		}
	}

	// 5. Threat Intel: Tor Exit Node Check
	e.mu.RLock()
	if _, isTor := e.torIPs[ipStr]; isTor {
		rec["_is_tor"] = "true"
	}

	// 6. Threat Intel: Known Scanner Check
	for _, sr := range e.scanners {
		if sr.IPNet.Contains(parsedIP) {
			rec["_scanner"] = sr.Name
			break
		}
	}
	e.mu.RUnlock()

	// 7. TLS Fingerprinting (JA3 / JA4)
	if e.tlsRegistry != nil {
		if fp, ok := e.tlsRegistry.GetFingerprint(hostStr); ok {
			rec["_ja3"] = fp.JA3
			rec["_ja4"] = fp.JA4
			if fp.SNI != "" {
				rec["_sni"] = fp.SNI
			}
		}
	}
}

// AddTorIP adds an IP to the Tor exit node set (useful for runtime updates and unit tests)
func (e *Enricher) AddTorIP(ip string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.torIPs[strings.TrimSpace(ip)] = struct{}{}
}

// AddScannerCIDR adds a scanner CIDR range (useful for runtime updates and unit tests)
func (e *Enricher) AddScannerCIDR(cidr string, name string) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.scanners = append(e.scanners, ScannerRange{IPNet: ipnet, Name: name})
	return nil
}

func (e *Enricher) resolvePTR(ip string) (string, bool) {
	if val, ok := e.rdnsCache.Load(ip); ok {
		return val.(string), true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	resolver := net.DefaultResolver
	names, err := resolver.LookupAddr(ctx, ip)
	if err == nil && len(names) > 0 {
		clean := strings.TrimSuffix(names[0], ".")
		e.rdnsCache.Store(ip, clean)
		return clean, true
	}

	e.rdnsCache.Store(ip, "")
	return "", false
}

func (e *Enricher) loadDefaultScanners() {
	defaultScanners := []struct {
		cidr string
		name string
	}{
		// Shodan
		{"185.180.143.0/24", "shodan"},
		{"198.20.69.0/24", "shodan"},
		{"198.20.70.0/24", "shodan"},
		{"198.20.99.0/24", "shodan"},
		{"208.180.20.0/24", "shodan"},
		{"209.126.110.0/24", "shodan"},
		{"66.240.236.0/24", "shodan"},
		{"71.6.135.0/24", "shodan"},
		{"71.6.146.0/24", "shodan"},
		{"71.6.158.0/24", "shodan"},
		{"71.6.165.0/24", "shodan"},
		{"71.6.167.0/24", "shodan"},
		{"89.248.167.0/24", "shodan"},
		{"93.120.27.0/24", "shodan"},
		// Censys
		{"162.142.125.0/24", "censys"},
		{"167.94.138.0/24", "censys"},
		{"167.94.145.0/24", "censys"},
		{"167.94.146.0/24", "censys"},
		{"167.248.133.0/24", "censys"},
		{"192.35.168.0/23", "censys"},
		{"206.168.32.0/21", "censys"},
		// Shadowserver
		{"184.105.139.0/24", "shadowserver"},
		{"184.105.247.0/24", "shadowserver"},
		{"216.218.206.0/24", "shadowserver"},
		{"64.88.241.0/24", "shadowserver"},
		// BinaryEdge
		{"185.94.111.0/24", "binaryedge"},
		{"185.220.101.0/24", "binaryedge"},
	}

	for _, ds := range defaultScanners {
		_ = e.AddScannerCIDR(ds.cidr, ds.name)
	}
}

func (e *Enricher) loadScannerFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Warnf("failed to open scanner list file %s: %v", path, err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			_ = e.AddScannerCIDR(parts[0], parts[1])
		} else if len(parts) == 1 {
			_ = e.AddScannerCIDR(parts[0], "scanner")
		}
	}
}

func (e *Enricher) loadTorFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Warnf("failed to open tor list file %s: %v", path, err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		e.AddTorIP(line)
	}
}
