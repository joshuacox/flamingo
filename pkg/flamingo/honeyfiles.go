package flamingo

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// Honeyfile defines a synthetic deception trap file
type Honeyfile struct {
	Path        string
	ContentType string
	Content     string
	Description string
}

// HoneyfileManager manages virtual breadcrumbs and files across web listeners
type HoneyfileManager struct {
	mu    sync.RWMutex
	files map[string]Honeyfile
}

// NewHoneyfileManager creates a manager with high-value default deception traps
func NewHoneyfileManager() *HoneyfileManager {
	hm := &HoneyfileManager{
		files: make(map[string]Honeyfile),
	}

	defaults := []Honeyfile{
		{
			Path:        "/.env",
			ContentType: "text/plain; charset=utf-8",
			Content: `# Production Environment Variables
APP_ENV=production
APP_SECRET=canary_sec_991823908123019283019
DATABASE_URL=postgres://app_admin:CanaryProdDb99!@db.internal.corp:5432/production
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
JWT_SIGNING_KEY=secret-token-canary-key-99182
`,
			Description: "Environment configuration breadcrumb",
		},
		{
			Path:        "/passwords.txt",
			ContentType: "text/plain; charset=utf-8",
			Content: `# Corporate Internal Credentials (CONFIDENTIAL)
# Last Updated: 2026-01-15
admin: Summer2026!SecureRoot
backup_operator: B@ckupVault9928!
sql_admin: SqlEnterpriseM@ster2026
vpn_gateway: RemoteAccessKey99182
`,
			Description: "Internal passwords breadcrumb",
		},
		{
			Path:        "/.git/config",
			ContentType: "text/plain; charset=utf-8",
			Content: `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
[remote "origin"]
	url = git@github.internal.corp:devops/production-infrastructure.git
	fetch = +refs/heads/*:refs/remotes/origin/*
`,
			Description: "Git repository configuration breadcrumb",
		},
		{
			Path:        "/.aws/credentials",
			ContentType: "text/plain; charset=utf-8",
			Content: `[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1
`,
			Description: "AWS credentials breadcrumb",
		},
		{
			Path:        "/backup.sql",
			ContentType: "application/sql",
			Content: `-- MySQL dump 10.13  Distrib 8.0.35, for Linux (x86_64)
-- Host: localhost    Database: enterprise_prod
-- Table structure for table 'users'
DROP TABLE IF EXISTS users;
CREATE TABLE users (
  id int NOT NULL AUTO_INCREMENT,
  username varchar(50) NOT NULL,
  password_hash varchar(255) NOT NULL,
  email varchar(100) DEFAULT NULL,
  PRIMARY KEY (id)
);
INSERT INTO users VALUES (1,'admin','$2a$12$e8p2W6hO0pU1qV/9O2q2xeYkE7a7nQ9F2H1j8k3l0m','admin@internal.corp');
`,
			Description: "Database backup breadcrumb",
		},
		{
			Path:        "/id_rsa",
			ContentType: "text/plain; charset=utf-8",
			Content: `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACD7V0b5kH0O1l2L8rJ4h2j3k4l5m6n7o8p9q0r1s2t3u4AAAJD4t5uA+L
ebgAAAAAtzc2gtZWQyNTUxOQAAACD7V0b5kH0O1l2L8rJ4h2j3k4l5m6n7o8p9q0r1s2
t3u4AAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAHJvb3RAcHJvZA==
-----END OPENSSH PRIVATE KEY-----
`,
			Description: "SSH private key breadcrumb",
		},
	}

	for _, hf := range defaults {
		hm.AddHoneyfile(hf)
	}

	return hm
}

// AddHoneyfile registers or replaces a virtual honeyfile
func (hm *HoneyfileManager) AddHoneyfile(hf Honeyfile) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	cleanPath := "/" + strings.TrimLeft(hf.Path, "/")
	hm.files[cleanPath] = hf
}

// Match checks if a path corresponds to a virtual honeyfile
func (hm *HoneyfileManager) Match(path string) (Honeyfile, bool) {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	cleanPath := "/" + strings.TrimLeft(path, "/")
	hf, ok := hm.files[cleanPath]
	return hf, ok
}

// GlobalHoneyfiles is the singleton instance for honeyfile traps
var GlobalHoneyfiles = NewHoneyfileManager()

// ServeHoneyfile checks if the incoming request matches a honeyfile, records the access event, and serves it
func ServeHoneyfile(w http.ResponseWriter, r *http.Request, rw *RecordWriter, proto string) bool {
	hf, ok := GlobalHoneyfiles.Match(r.URL.Path)
	if !ok {
		return false
	}

	if rw != nil {
		rw.Record("honeyfile", proto, r.RemoteAddr, map[string]string{
			"honeyfile":   hf.Path,
			"description": hf.Description,
			"method":      r.Method,
			"path":        r.URL.Path,
			"agent":       r.UserAgent(),
		})
	}

	w.Header().Set("Content-Type", hf.ContentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(hf.Content)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(hf.Content))
	return true
}
