package flamingo

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ConfigFile represents the structure of flamingo.yaml
type ConfigFile struct {
	Quiet              *bool         `yaml:"quiet,omitempty"`
	Verbose            *bool         `yaml:"verbose,omitempty"`
	DontIgnoreFailures *bool         `yaml:"dontIgnoreFailures,omitempty"`
	Protocols          string        `yaml:"protocols,omitempty"`
	Outputs            []string      `yaml:"outputs,omitempty"`
	Ports              ConfigPorts   `yaml:"ports,omitempty"`
	Banners            ConfigBanners `yaml:"banners,omitempty"`
	HTTP               ConfigHTTP    `yaml:"http,omitempty"`
	TLS                ConfigTLS     `yaml:"tls,omitempty"`
	DNS                ConfigDNS     `yaml:"dns,omitempty"`
	SSH                ConfigSSH     `yaml:"ssh,omitempty"`
	Metrics            ConfigMetrics `yaml:"metrics,omitempty"`
}

type ConfigPorts struct {
	FTP      string `yaml:"ftp,omitempty"`
	SSH      string `yaml:"ssh,omitempty"`
	DNS      string `yaml:"dns,omitempty"`
	SNMP     string `yaml:"snmp,omitempty"`
	LDAP     string `yaml:"ldap,omitempty"`
	LDAPS    string `yaml:"ldaps,omitempty"`
	HTTP     string `yaml:"http,omitempty"`
	HTTPS    string `yaml:"https,omitempty"`
	IMAP     string `yaml:"imap,omitempty"`
	IMAPS    string `yaml:"imaps,omitempty"`
	POP3     string `yaml:"pop3,omitempty"`
	POP3S    string `yaml:"pop3s,omitempty"`
	SMTP     string `yaml:"smtp,omitempty"`
	SMTPS    string `yaml:"smtps,omitempty"`
	Redis    string `yaml:"redis,omitempty"`
	Telnet   string `yaml:"telnet,omitempty"`
	Postgres string `yaml:"postgres,omitempty"`
	MySQL    string `yaml:"mysql,omitempty"`
	MongoDB  string `yaml:"mongodb,omitempty"`
	SMB       string `yaml:"smb,omitempty"`
	WinRM     string `yaml:"winrm,omitempty"`
	WinRMS    string `yaml:"winrms,omitempty"`
	Kerberos  string `yaml:"kerberos,omitempty"`
	Docker    string `yaml:"docker,omitempty"`
	DockerTLS string `yaml:"dockertls,omitempty"`
	Kubelet   string `yaml:"kubelet,omitempty"`
	Etcd      string `yaml:"etcd,omitempty"`
	VNC       string `yaml:"vnc,omitempty"`
	MQTT      string `yaml:"mqtt,omitempty"`
	MQTTS     string `yaml:"mqtts,omitempty"`
}

type ConfigBanners struct {
	POP3   string `yaml:"pop3,omitempty"`
	SMTP   string `yaml:"smtp,omitempty"`
	Telnet string `yaml:"telnet,omitempty"`
	MySQL  string `yaml:"mysql,omitempty"`
}

type ConfigHTTP struct {
	Realm    string `yaml:"realm,omitempty"`
	AuthMode string `yaml:"authMode,omitempty"`
}

type ConfigTLS struct {
	CertFile string `yaml:"certFile,omitempty"`
	KeyFile  string `yaml:"keyFile,omitempty"`
	Name     string `yaml:"name,omitempty"`
	Org      string `yaml:"org,omitempty"`
}

type ConfigDNS struct {
	ResolveToIP string `yaml:"resolveToIP,omitempty"`
}

type ConfigSSH struct {
	HostKey string `yaml:"hostKey,omitempty"`
}

type ConfigMetrics struct {
	Enabled *bool  `yaml:"enabled,omitempty"`
	Port    uint16 `yaml:"port,omitempty"`
}

// LoadConfigFile parses a YAML configuration file from disk.
func LoadConfigFile(path string) (*ConfigFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	var cfg ConfigFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse yaml config file %s: %w", path, err)
	}

	return &cfg, nil
}
