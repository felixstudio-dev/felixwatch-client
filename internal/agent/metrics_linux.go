//go:build linux

package agent

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/felixstudio-dev/felixwatch-client/internal/protocol"
)

type cpuSample struct {
	total uint64
	idle  uint64
}

func readCPU() (cpuSample, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuSample{}, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	if !s.Scan() {
		return cpuSample{}, fmt.Errorf("/proc/stat missing cpu line")
	}
	parts := strings.Fields(s.Text())
	if len(parts) < 5 || parts[0] != "cpu" {
		return cpuSample{}, fmt.Errorf("unexpected /proc/stat cpu line")
	}
	var total, idle uint64
	for i := 1; i < len(parts); i++ {
		v, err := strconv.ParseUint(parts[i], 10, 64)
		if err != nil {
			return cpuSample{}, err
		}
		total += v
		if i == 4 || i == 5 {
			idle += v
		}
	}
	return cpuSample{total: total, idle: idle}, nil
}

func cpuPercent() (float64, error) {
	a, err := readCPU()
	if err != nil {
		return 0, err
	}
	time.Sleep(200 * time.Millisecond)
	b, err := readCPU()
	if err != nil {
		return 0, err
	}
	dt := b.total - a.total
	di := b.idle - a.idle
	if dt == 0 {
		return 0, nil
	}
	return float64(dt-di) * 100 / float64(dt), nil
}

func readMemInfo() (map[string]uint64, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]uint64{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		parts := strings.Fields(s.Text())
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSuffix(parts[0], ":")
		v, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			continue
		}
		out[key] = v * 1024
	}
	return out, s.Err()
}

func readFirstFloat(path string) (float64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	parts := strings.Fields(string(b))
	if len(parts) == 0 {
		return 0, fmt.Errorf("empty %s", path)
	}
	return strconv.ParseFloat(parts[0], 64)
}

func readUptime() (uint64, error) {
	v, err := readFirstFloat("/proc/uptime")
	return uint64(v), err
}

func fsUsage(path string) (diskPct, inodePct float64, err error) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(path, &s); err != nil {
		return 0, 0, err
	}
	if s.Blocks > 0 {
		diskPct = float64(s.Blocks-s.Bavail) * 100 / float64(s.Blocks)
	}
	if s.Files > 0 {
		inodePct = float64(s.Files-s.Ffree) * 100 / float64(s.Files)
	}
	return diskPct, inodePct, nil
}

func CollectMetrics() (protocol.Metrics, error) {
	cpu, err := cpuPercent()
	if err != nil {
		return protocol.Metrics{}, err
	}
	mem, err := readMemInfo()
	if err != nil {
		return protocol.Metrics{}, err
	}
	uptime, err := readUptime()
	if err != nil {
		return protocol.Metrics{}, err
	}
	load1, err := readFirstFloat("/proc/loadavg")
	if err != nil {
		return protocol.Metrics{}, err
	}
	disk, inode, err := fsUsage("/")
	if err != nil {
		return protocol.Metrics{}, err
	}
	used := uint64(0)
	if mem["MemTotal"] > mem["MemAvailable"] {
		used = mem["MemTotal"] - mem["MemAvailable"]
	}
	swapUsed := uint64(0)
	if mem["SwapTotal"] > mem["SwapFree"] {
		swapUsed = mem["SwapTotal"] - mem["SwapFree"]
	}
	return protocol.Metrics{
		UptimeSeconds:    uptime,
		CPUPercent:       cpu,
		MemoryTotalBytes: mem["MemTotal"],
		MemoryUsedBytes:  used,
		SwapTotalBytes:   mem["SwapTotal"],
		SwapUsedBytes:    swapUsed,
		Load1:            load1,
		DiskUsedPercent:  disk,
		InodeUsedPercent: inode,
	}, nil
}
