//go:build linux

package agent

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/felixstudio-dev/felixwatch-client/internal/config"
	"github.com/felixstudio-dev/felixwatch-client/internal/protocol"
)

func TestCheckServiceUsesOnlyConfiguredPIDFileAndComm(t *testing.T) {
	commBytes, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		t.Fatal(err)
	}
	comm := strings.TrimSpace(string(commBytes))
	pidFile := filepath.Join(t.TempDir(), "service.pid")
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	got := CheckServices([]config.ServiceCheckConfig{{ServiceID: "collector", PIDFile: pidFile, ExpectedComm: comm, Essential: true}})
	if len(got) != 1 {
		t.Fatalf("expected one service result, got %d", len(got))
	}
	if got[0].State != protocol.StateHealthy || got[0].Detail != "running" || !got[0].Essential {
		t.Fatalf("unexpected service health: %#v", got[0])
	}
	if strings.Contains(got[0].Detail, pidFile) || strings.Contains(got[0].Detail, strconv.Itoa(os.Getpid())) {
		t.Fatal("service health detail must not expose PID or pid-file path")
	}
}

func TestCheckServiceRejectsPIDIdentityMismatch(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "service.pid")
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}
	got := CheckServices([]config.ServiceCheckConfig{{ServiceID: "collector", PIDFile: pidFile, ExpectedComm: "definitely-not-this-process"}})
	if len(got) != 1 || got[0].State != protocol.StateDown || got[0].Detail != "process_identity_mismatch" {
		t.Fatalf("expected identity mismatch DOWN, got %#v", got)
	}
}

func TestCheckServiceMissingPIDFileIsDownWithoutSensitiveDetail(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "missing.pid")
	got := CheckServices([]config.ServiceCheckConfig{{ServiceID: "web", PIDFile: pidFile}})
	if len(got) != 1 || got[0].State != protocol.StateDown || got[0].Detail != "pid_file_missing" {
		t.Fatalf("expected missing pid file DOWN, got %#v", got)
	}
	if strings.Contains(got[0].Detail, pidFile) {
		t.Fatal("detail must not expose configured path")
	}
}
