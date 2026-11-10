//go:build !linux

package agent

import (
	"github.com/felixstudio-dev/felixwatch-client/internal/config"
	"github.com/felixstudio-dev/felixwatch-client/internal/protocol"
)

func CheckServices(checks []config.ServiceCheckConfig) []protocol.ServiceHealth {
	if len(checks) == 0 {
		return nil
	}
	out := make([]protocol.ServiceHealth, 0, len(checks))
	for _, check := range checks {
		out = append(out, protocol.ServiceHealth{ServiceID: check.ServiceID, Essential: check.Essential, State: protocol.StateUnknown, Detail: "unsupported_platform"})
	}
	return out
}
