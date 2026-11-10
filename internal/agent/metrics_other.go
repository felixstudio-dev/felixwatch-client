//go:build !linux

package agent

import (
	"errors"

	"github.com/felixstudio-dev/felixwatch-client/internal/protocol"
)

func CollectMetrics() (protocol.Metrics, error) {
	return protocol.Metrics{}, errors.New("system metrics collector is implemented for Linux in foundation v1")
}
