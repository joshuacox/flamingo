package cmd

import (
	"fmt"
	"os"

	"github.com/atredispartners/flamingo/pkg/flamingo"
	"github.com/spf13/cobra"
)

// ToolName controls what this program thinks it is
var ToolName = "flamingo"

// Version is set by goreleaser
var Version = "0.0.0"

type flamingoParameters struct {
	ConfigFile         string
	Quiet              bool
	Verbose            bool
	DontIgnoreFailures bool
	FTPPorts           string
	IMAPPorts          string
	IMAPSPorts         string
	POP3Ports          string
	POP3SPorts         string
	SMTPPorts          string
	SMTPSPorts         string
	RedisPorts         string
	TelnetPorts        string
	PostgresPorts      string
	MySQLPorts         string
	MySQLBanner        string
	MongoDBPorts       string
	SMBPorts           string
	WinRMPorts         string
	WinRMSPorts        string
	KerberosPorts      string
	DockerPorts        string
	DockerTLSPorts     string
	KubeletPorts       string
	EtcdPorts          string
	VNCPorts           string
	MQTTPorts          string
	MQTTSPorts         string
	MetricsPort        uint16
	EnableMetrics      bool
	POP3Banner         string
	SMTPBanner         string
	TelnetBanner       string
	DNSPorts           string
	DNSResolveToIP     string
	SNMPPorts          string
	SSHPorts           string
	SSHHostKey         string
	LDAPPorts          string
	LDAPSPorts         string
	HTTPPorts          string
	HTTPSPorts         string
	HTTPBasicRealm     string
	HTTPAuthMode       string
	TLSCertFile        string
	TLSCertData        string
	TLSKeyFile         string
	TLSKeyData         string
	TLSName            string
	TLSOrgName         string
	Protocols          string
	ConfigOutputs      []string
	GeoIPCityDB        string
	GeoIPASNDB         string
	EnableRDNS         bool
	TorList            string
	ScannerList        string
	TarpitThreshold    int
	TarpitDelay        string
}

var params = &flamingoParameters{}

var rootCmd = &cobra.Command{
	Use:   ToolName,
	Short: fmt.Sprintf("%s captures inbound credentials", ToolName),
	Long:  fmt.Sprintf(`flamingo v%s`, Version),
	Args:  cobra.ArbitraryArgs,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if params.ConfigFile != "" {
			cfg, err := flamingo.LoadConfigFile(params.ConfigFile)
			if err != nil {
				return err
			}
			applyConfigFile(cmd, cfg)
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		startCapture(cmd, args)
	},
}

func applyConfigFile(cmd *cobra.Command, cfg *flamingo.ConfigFile) {
	if cfg.Quiet != nil && !cmd.Flags().Changed("quiet") {
		params.Quiet = *cfg.Quiet
	}
	if cfg.Verbose != nil && !cmd.Flags().Changed("verbose") {
		params.Verbose = *cfg.Verbose
	}
	if cfg.DontIgnoreFailures != nil && !cmd.Flags().Changed("dont-ignore") {
		params.DontIgnoreFailures = *cfg.DontIgnoreFailures
	}
	if cfg.Protocols != "" && !cmd.Flags().Changed("protocols") {
		params.Protocols = cfg.Protocols
	}

	// Ports
	if cfg.Ports.FTP != "" && !cmd.Flags().Changed("ftp-ports") {
		params.FTPPorts = cfg.Ports.FTP
	}
	if cfg.Ports.SSH != "" && !cmd.Flags().Changed("ssh-ports") {
		params.SSHPorts = cfg.Ports.SSH
	}
	if cfg.Ports.DNS != "" && !cmd.Flags().Changed("dns-ports") {
		params.DNSPorts = cfg.Ports.DNS
	}
	if cfg.Ports.SNMP != "" && !cmd.Flags().Changed("snmp-ports") {
		params.SNMPPorts = cfg.Ports.SNMP
	}
	if cfg.Ports.LDAP != "" && !cmd.Flags().Changed("ldap-ports") {
		params.LDAPPorts = cfg.Ports.LDAP
	}
	if cfg.Ports.LDAPS != "" && !cmd.Flags().Changed("ldaps-ports") {
		params.LDAPSPorts = cfg.Ports.LDAPS
	}
	if cfg.Ports.HTTP != "" && !cmd.Flags().Changed("http-ports") {
		params.HTTPPorts = cfg.Ports.HTTP
	}
	if cfg.Ports.HTTPS != "" && !cmd.Flags().Changed("https-ports") {
		params.HTTPSPorts = cfg.Ports.HTTPS
	}
	if cfg.Ports.IMAP != "" && !cmd.Flags().Changed("imap-ports") {
		params.IMAPPorts = cfg.Ports.IMAP
	}
	if cfg.Ports.IMAPS != "" && !cmd.Flags().Changed("imaps-ports") {
		params.IMAPSPorts = cfg.Ports.IMAPS
	}
	if cfg.Ports.POP3 != "" && !cmd.Flags().Changed("pop3-ports") {
		params.POP3Ports = cfg.Ports.POP3
	}
	if cfg.Ports.POP3S != "" && !cmd.Flags().Changed("pop3s-ports") {
		params.POP3SPorts = cfg.Ports.POP3S
	}
	if cfg.Ports.SMTP != "" && !cmd.Flags().Changed("smtp-ports") {
		params.SMTPPorts = cfg.Ports.SMTP
	}
	if cfg.Ports.SMTPS != "" && !cmd.Flags().Changed("smtps-ports") {
		params.SMTPSPorts = cfg.Ports.SMTPS
	}
	if cfg.Ports.Redis != "" && !cmd.Flags().Changed("redis-ports") {
		params.RedisPorts = cfg.Ports.Redis
	}
	if cfg.Ports.Telnet != "" && !cmd.Flags().Changed("telnet-ports") {
		params.TelnetPorts = cfg.Ports.Telnet
	}
	if cfg.Ports.Postgres != "" && !cmd.Flags().Changed("postgres-ports") {
		params.PostgresPorts = cfg.Ports.Postgres
	}
	if cfg.Ports.MySQL != "" && !cmd.Flags().Changed("mysql-ports") {
		params.MySQLPorts = cfg.Ports.MySQL
	}
	if cfg.Ports.MongoDB != "" && !cmd.Flags().Changed("mongodb-ports") {
		params.MongoDBPorts = cfg.Ports.MongoDB
	}
	if cfg.Ports.SMB != "" && !cmd.Flags().Changed("smb-ports") {
		params.SMBPorts = cfg.Ports.SMB
	}
	if cfg.Ports.WinRM != "" && !cmd.Flags().Changed("winrm-ports") {
		params.WinRMPorts = cfg.Ports.WinRM
	}
	if cfg.Ports.WinRMS != "" && !cmd.Flags().Changed("winrms-ports") {
		params.WinRMSPorts = cfg.Ports.WinRMS
	}
	if cfg.Ports.Kerberos != "" && !cmd.Flags().Changed("kerberos-ports") {
		params.KerberosPorts = cfg.Ports.Kerberos
	}
	if cfg.Ports.Docker != "" && !cmd.Flags().Changed("docker-ports") {
		params.DockerPorts = cfg.Ports.Docker
	}
	if cfg.Ports.DockerTLS != "" && !cmd.Flags().Changed("dockertls-ports") {
		params.DockerTLSPorts = cfg.Ports.DockerTLS
	}
	if cfg.Ports.Kubelet != "" && !cmd.Flags().Changed("kubelet-ports") {
		params.KubeletPorts = cfg.Ports.Kubelet
	}
	if cfg.Ports.Etcd != "" && !cmd.Flags().Changed("etcd-ports") {
		params.EtcdPorts = cfg.Ports.Etcd
	}
	if cfg.Ports.VNC != "" && !cmd.Flags().Changed("vnc-ports") {
		params.VNCPorts = cfg.Ports.VNC
	}
	if cfg.Ports.MQTT != "" && !cmd.Flags().Changed("mqtt-ports") {
		params.MQTTPorts = cfg.Ports.MQTT
	}
	if cfg.Ports.MQTTS != "" && !cmd.Flags().Changed("mqtts-ports") {
		params.MQTTSPorts = cfg.Ports.MQTTS
	}

	// Banners
	if cfg.Banners.POP3 != "" && !cmd.Flags().Changed("pop3-banner") {
		params.POP3Banner = cfg.Banners.POP3
	}
	if cfg.Banners.SMTP != "" && !cmd.Flags().Changed("smtp-banner") {
		params.SMTPBanner = cfg.Banners.SMTP
	}
	if cfg.Banners.Telnet != "" && !cmd.Flags().Changed("telnet-banner") {
		params.TelnetBanner = cfg.Banners.Telnet
	}
	if cfg.Banners.MySQL != "" && !cmd.Flags().Changed("mysql-banner") {
		params.MySQLBanner = cfg.Banners.MySQL
	}

	// DNS, SSH, HTTP, TLS, Metrics
	if cfg.DNS.ResolveToIP != "" && !cmd.Flags().Changed("dns-resolve-to") {
		params.DNSResolveToIP = cfg.DNS.ResolveToIP
	}
	if cfg.SSH.HostKey != "" && !cmd.Flags().Changed("ssh-host-key") {
		params.SSHHostKey = cfg.SSH.HostKey
	}
	if cfg.HTTP.Realm != "" && !cmd.Flags().Changed("http-realm") {
		params.HTTPBasicRealm = cfg.HTTP.Realm
	}
	if cfg.HTTP.AuthMode != "" && !cmd.Flags().Changed("http-auth-mode") {
		params.HTTPAuthMode = cfg.HTTP.AuthMode
	}
	if cfg.TLS.CertFile != "" && !cmd.Flags().Changed("tls-cert") {
		params.TLSCertFile = cfg.TLS.CertFile
	}
	if cfg.TLS.KeyFile != "" && !cmd.Flags().Changed("tls-key") {
		params.TLSKeyFile = cfg.TLS.KeyFile
	}
	if cfg.TLS.Name != "" && !cmd.Flags().Changed("tls-name") {
		params.TLSName = cfg.TLS.Name
	}
	if cfg.TLS.Org != "" && !cmd.Flags().Changed("tls-org") {
		params.TLSOrgName = cfg.TLS.Org
	}
	if cfg.Metrics.Enabled != nil && !cmd.Flags().Changed("metrics") {
		params.EnableMetrics = *cfg.Metrics.Enabled
	}
	if cfg.Metrics.Port != 0 && !cmd.Flags().Changed("metrics-port") {
		params.MetricsPort = cfg.Metrics.Port
	}
	if len(cfg.Outputs) > 0 {
		params.ConfigOutputs = cfg.Outputs
	}

	// Threat intelligence & enrichment
	if cfg.Enrichment.GeoIPCityDB != "" && !cmd.Flags().Changed("geoip-db") {
		params.GeoIPCityDB = cfg.Enrichment.GeoIPCityDB
	}
	if cfg.Enrichment.GeoIPASNDB != "" && !cmd.Flags().Changed("asn-db") {
		params.GeoIPASNDB = cfg.Enrichment.GeoIPASNDB
	}
	if cfg.Enrichment.EnableRDNS != nil && !cmd.Flags().Changed("enable-rdns") {
		params.EnableRDNS = *cfg.Enrichment.EnableRDNS
	}
	if cfg.Enrichment.TorList != "" && !cmd.Flags().Changed("tor-list") {
		params.TorList = cfg.Enrichment.TorList
	}
	if cfg.Enrichment.ScannerList != "" && !cmd.Flags().Changed("scanner-list") {
		params.ScannerList = cfg.Enrichment.ScannerList
	}

	// Anti-bruteforce tarpit
	if cfg.Tarpit.Threshold != nil && !cmd.Flags().Changed("tarpit-threshold") {
		params.TarpitThreshold = *cfg.Tarpit.Threshold
	}
	if cfg.Tarpit.Delay != "" && !cmd.Flags().Changed("tarpit-delay") {
		params.TarpitDelay = cfg.Tarpit.Delay
	}
}

// Execute is the main entry point for this tool
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	// Configuration file option
	rootCmd.PersistentFlags().StringVarP(&params.ConfigFile, "config", "c", "", "Path to YAML configuration file")

	// General options
	rootCmd.PersistentFlags().BoolVarP(&params.Verbose, "verbose", "v", false, "Display verbose output")
	rootCmd.PersistentFlags().BoolVarP(&params.Quiet, "quiet", "q", false, "Hide startup banners and other extraneous output")
	rootCmd.PersistentFlags().BoolVarP(&params.DontIgnoreFailures, "dont-ignore", "", false, "Treat individual listener failures as fatal")

	rootCmd.Flags().StringVarP(&params.Protocols, "protocols", "", "ssh,snmp,ldap,http,dns,ftp,imap,pop3,smtp,redis,telnet,postgres,mysql,mongodb,smb,winrm,kerberos,docker,kubelet,etcd,vnc,mqtt", "Specify a comma-separated list of protocols")

	// SNMP parameters
	rootCmd.Flags().StringVarP(&params.SNMPPorts, "snmp-ports", "", "161", "The list of UDP ports to listen on for SNMP")

	// SSH parameters
	rootCmd.Flags().StringVarP(&params.SSHPorts, "ssh-ports", "", "22", "The list of TCP ports to listen on for SSH")
	rootCmd.Flags().StringVarP(&params.SSHHostKey, "ssh-host-key", "", "", "An optional path to a SSH host key on disk")

	// LDAP(S) parameters
	rootCmd.Flags().StringVarP(&params.LDAPPorts, "ldap-ports", "", "389", "The list of TCP ports to listen on for LDAP")
	rootCmd.Flags().StringVarP(&params.LDAPSPorts, "ldaps-ports", "", "636", "The list of TCP ports to listen on for LDAPS")

	// DNS parameters
	rootCmd.Flags().StringVarP(&params.DNSPorts, "dns-ports", "", "53,5353", "The list of UDP ports to listen on for DNS")
	rootCmd.Flags().StringVarP(&params.DNSResolveToIP, "dns-resolve-to", "", "", "The IP address used to respond to DNS Type A question. If empty, no response will be sent")

	// FTP parameters
	rootCmd.Flags().StringVarP(&params.FTPPorts, "ftp-ports", "", "21", "The list of TCP ports to listen on for FTP")

	// IMAP(S) parameters
	rootCmd.Flags().StringVarP(&params.IMAPPorts, "imap-ports", "", "143", "The list of TCP ports to listen on for IMAP")
	rootCmd.Flags().StringVarP(&params.IMAPSPorts, "imaps-ports", "", "993", "The list of TCP ports to listen on for IMAPS")

	// POP3(S) parameters
	rootCmd.Flags().StringVarP(&params.POP3Ports, "pop3-ports", "", "110", "The list of TCP ports to listen on for POP3")
	rootCmd.Flags().StringVarP(&params.POP3SPorts, "pop3s-ports", "", "995", "The list of TCP ports to listen on for POP3S")
	rootCmd.Flags().StringVarP(&params.POP3Banner, "pop3-banner", "", "+OK Flamingo POP3 server ready", "POP3 server greeting banner")

	// SMTP(S) parameters
	rootCmd.Flags().StringVarP(&params.SMTPPorts, "smtp-ports", "", "25,587", "The list of TCP ports to listen on for SMTP")
	rootCmd.Flags().StringVarP(&params.SMTPSPorts, "smtps-ports", "", "465", "The list of TCP ports to listen on for SMTPS")
	rootCmd.Flags().StringVarP(&params.SMTPBanner, "smtp-banner", "", "220 Flamingo ESMTP Service ready", "SMTP server greeting banner")

	// Redis parameters
	rootCmd.Flags().StringVarP(&params.RedisPorts, "redis-ports", "", "6379", "The list of TCP ports to listen on for Redis")

	// Telnet parameters
	rootCmd.Flags().StringVarP(&params.TelnetPorts, "telnet-ports", "", "23", "The list of TCP ports to listen on for Telnet")
	rootCmd.Flags().StringVarP(&params.TelnetBanner, "telnet-banner", "", "Flamingo Honeypot Telnet Service\r\n", "Telnet server greeting banner")

	// Database parameters
	rootCmd.Flags().StringVarP(&params.PostgresPorts, "postgres-ports", "", "5432", "The list of TCP ports to listen on for PostgreSQL")
	rootCmd.Flags().StringVarP(&params.MySQLPorts, "mysql-ports", "", "3306", "The list of TCP ports to listen on for MySQL")
	rootCmd.Flags().StringVarP(&params.MySQLBanner, "mysql-banner", "", "8.0.35", "MySQL server version banner to display")
	rootCmd.Flags().StringVarP(&params.MongoDBPorts, "mongodb-ports", "", "27017", "The list of TCP ports to listen on for MongoDB")

	// Enterprise & lateral movement parameters
	rootCmd.Flags().StringVarP(&params.SMBPorts, "smb-ports", "", "445", "The list of TCP ports to listen on for SMB")
	rootCmd.Flags().StringVarP(&params.WinRMPorts, "winrm-ports", "", "5985", "The list of TCP ports to listen on for WinRM (HTTP)")
	rootCmd.Flags().StringVarP(&params.WinRMSPorts, "winrms-ports", "", "5986", "The list of TCP ports to listen on for WinRM (HTTPS)")
	rootCmd.Flags().StringVarP(&params.KerberosPorts, "kerberos-ports", "", "88", "The list of TCP/UDP ports to listen on for Kerberos")
	rootCmd.Flags().StringVarP(&params.DockerPorts, "docker-ports", "", "2375", "The list of TCP ports to listen on for Docker Engine API (HTTP)")
	rootCmd.Flags().StringVarP(&params.DockerTLSPorts, "dockertls-ports", "", "2376", "The list of TCP ports to listen on for Docker Engine API (HTTPS)")
	rootCmd.Flags().StringVarP(&params.KubeletPorts, "kubelet-ports", "", "10250", "The list of TCP ports to listen on for Kubelet API (HTTPS)")
	rootCmd.Flags().StringVarP(&params.EtcdPorts, "etcd-ports", "", "2379", "The list of TCP ports to listen on for etcd API")
	rootCmd.Flags().StringVarP(&params.VNCPorts, "vnc-ports", "", "5900", "The list of TCP ports to listen on for VNC")
	rootCmd.Flags().StringVarP(&params.MQTTPorts, "mqtt-ports", "", "1883", "The list of TCP ports to listen on for MQTT")
	rootCmd.Flags().StringVarP(&params.MQTTSPorts, "mqtts-ports", "", "8883", "The list of TCP ports to listen on for MQTT (TLS)")

	// Metrics parameters
	rootCmd.Flags().BoolVarP(&params.EnableMetrics, "metrics", "", false, "Enable Prometheus metrics HTTP server")
	rootCmd.Flags().Uint16VarP(&params.MetricsPort, "metrics-port", "", 9090, "Port for Prometheus metrics HTTP server")

	// HTTP(S) parameters
	rootCmd.Flags().StringVarP(&params.HTTPPorts, "http-ports", "", "80", "The list of TCP ports to listen on for HTTP")
	rootCmd.Flags().StringVarP(&params.HTTPSPorts, "https-ports", "", "443", "The list of TCP ports to listen on for HTTPS")
	rootCmd.Flags().StringVarP(&params.HTTPBasicRealm, "http-realm", "", "Administration", "The HTTP basic authentication realm to present")
	rootCmd.Flags().StringVarP(&params.HTTPAuthMode, "http-auth-mode", "", "ntlm", "The authentication mode for the HTTP listeners (ntlm or basic)")

	rootCmd.Flags().StringVarP(&params.TLSCertFile, "tls-cert", "", "", "An optional x509 certificate for TLS listeners")
	rootCmd.Flags().StringVarP(&params.TLSKeyFile, "tls-key", "", "", "An optional x509 key for TLS listeners")
	rootCmd.Flags().StringVarP(&params.TLSName, "tls-name", "", "localhost", "A server name to use with TLS listeners")
	rootCmd.Flags().StringVarP(&params.TLSOrgName, "tls-org", "", "Flamingo Feed, Inc.", "An organization to use for self-signed certificates")

	// Threat intelligence & enrichment parameters
	rootCmd.Flags().StringVarP(&params.GeoIPCityDB, "geoip-db", "", "", "Path to MaxMind GeoLite2-City.mmdb database")
	rootCmd.Flags().StringVarP(&params.GeoIPASNDB, "asn-db", "", "", "Path to MaxMind GeoLite2-ASN.mmdb database")
	rootCmd.Flags().BoolVarP(&params.EnableRDNS, "enable-rdns", "", false, "Enable non-blocking reverse DNS lookups for client IP addresses")
	rootCmd.Flags().StringVarP(&params.TorList, "tor-list", "", "", "Optional path to custom list of Tor exit node IP addresses")
	rootCmd.Flags().StringVarP(&params.ScannerList, "scanner-list", "", "", "Optional path to custom list of scanner CIDR ranges and tags")

	// Deception & hardening parameters
	rootCmd.Flags().IntVarP(&params.TarpitThreshold, "tarpit-threshold", "", 0, "Max connection/request attempts per minute from an IP before tarpit delay (0 = disabled)")
	rootCmd.Flags().StringVarP(&params.TarpitDelay, "tarpit-delay", "", "3s", "Duration to delay tarpitted requests (e.g. 3s, 5s)")
}
