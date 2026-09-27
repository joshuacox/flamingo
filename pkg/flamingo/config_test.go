package flamingo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigFile(t *testing.T) {
	yamlContent := `
quiet: true
verbose: false
dontIgnoreFailures: true
protocols: "postgres,mysql,mongodb,redis"
outputs:
  - "stdout"
  - "es://http://elasticsearch:9200/flamingo"
ports:
  postgres: "5433"
  mysql: "3307"
  mongodb: "27018"
  docker: "2375"
  kubelet: "10250"
  vnc: "5901"
  mqtt: "1884"
banners:
  mysql: "8.0.35-deception"
metrics:
  enabled: true
  port: 9091
`
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "flamingo.yaml")
	if err := os.WriteFile(cfgPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write temp config file: %s", err)
	}

	cfg, err := LoadConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfigFile failed: %s", err)
	}

	if cfg.Quiet == nil || !*cfg.Quiet {
		t.Errorf("expected quiet to be true")
	}
	if cfg.Verbose == nil || *cfg.Verbose {
		t.Errorf("expected verbose to be false")
	}
	if cfg.DontIgnoreFailures == nil || !*cfg.DontIgnoreFailures {
		t.Errorf("expected dontIgnoreFailures to be true")
	}
	if cfg.Protocols != "postgres,mysql,mongodb,redis" {
		t.Errorf("unexpected protocols: %s", cfg.Protocols)
	}
	if len(cfg.Outputs) != 2 || cfg.Outputs[1] != "es://http://elasticsearch:9200/flamingo" {
		t.Errorf("unexpected outputs: %v", cfg.Outputs)
	}
	if cfg.Ports.Postgres != "5433" || cfg.Ports.MySQL != "3307" || cfg.Ports.MongoDB != "27018" || cfg.Ports.Docker != "2375" || cfg.Ports.Kubelet != "10250" || cfg.Ports.VNC != "5901" || cfg.Ports.MQTT != "1884" {
		t.Errorf("unexpected ports: %+v", cfg.Ports)
	}
	if cfg.Banners.MySQL != "8.0.35-deception" {
		t.Errorf("unexpected mysql banner: %s", cfg.Banners.MySQL)
	}
	if cfg.Metrics.Enabled == nil || !*cfg.Metrics.Enabled || cfg.Metrics.Port != 9091 {
		t.Errorf("unexpected metrics config: %+v", cfg.Metrics)
	}
}
