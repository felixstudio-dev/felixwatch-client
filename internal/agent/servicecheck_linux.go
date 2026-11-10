//go:build linux

package agent

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/felixstudio-dev/felixwatch-client/internal/config"
	"github.com/felixstudio-dev/felixwatch-client/internal/protocol"
)

const maxPIDFileBytes = 64

func checkService(check config.ServiceCheckConfig) protocol.ServiceHealth {
	result := protocol.ServiceHealth{ServiceID: check.ServiceID, Essential: check.Essential, State: protocol.StateDown}

	b, err := os.ReadFile(check.PIDFile)
	if err != nil {
		if os.IsNotExist(err) {
			result.Detail = "pid_file_missing"
			return result
		}
		result.State = protocol.StateUnknown
		result.Detail = "pid_file_unreadable"
		return result
	}
	if len(b) == 0 || len(b) > maxPIDFileBytes {
		result.State = protocol.StateUnknown
		result.Detail = "pid_file_invalid"
		return result
	}
	pidText := strings.TrimSpace(string(b))
	pid, err := strconv.Atoi(pidText)
	if err != nil || pid <= 1 {
		result.State = protocol.StateUnknown
		result.Detail = "pid_file_invalid"
		return result
	}

	commPath := filepath.Join("/proc", strconv.Itoa(pid), "comm")
	commBytes, err := os.ReadFile(commPath)
	if err != nil {
		if os.IsNotExist(err) {
			result.Detail = "process_absent"
			return result
		}
		result.State = protocol.StateUnknown
		result.Detail = "process_unreadable"
		return result
	}
	comm := strings.TrimSpace(string(commBytes))
	if check.ExpectedComm != "" && comm != check.ExpectedComm {
		result.Detail = "process_identity_mismatch"
		return result
	}
	result.State = protocol.StateHealthy
	result.Detail = "running"
	return result
}

func CheckServices(checks []config.ServiceCheckConfig) []protocol.ServiceHealth {
	if len(checks) == 0 {
		return nil
	}
	out := make([]protocol.ServiceHealth, 0, len(checks))
	for _, check := range checks {
		out = append(out, checkService(check))
	}
	return out
}
