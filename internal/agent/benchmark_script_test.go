package agent

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

func TestLinuxResourceBenchmarkProducesBoundedReceipt(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux /proc benchmark harness")
	}

	queuePath := filepath.Join(t.TempDir(), "queue.jsonl")
	if err := os.WriteFile(queuePath, []byte("bounded\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(t.TempDir(), "receipt.json")
	scriptPath := filepath.Join("..", "..", "scripts", "benchmark-linux.sh")
	cmd := exec.Command("sh", scriptPath,
		"--pid", strconv.Itoa(os.Getpid()),
		"--duration-seconds", "1",
		"--sample-seconds", "1",
		"--queue-path", queuePath,
		"--output", outputPath,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("benchmark harness failed: %v\n%s", err, output)
	}

	body, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		Profile      string `json:"profile"`
		Status       string `json:"status"`
		PID          int    `json:"pid"`
		Samples      int    `json:"samples"`
		Capabilities struct {
			ProcessIO bool `json:"process_io"`
		} `json:"capabilities"`
		Privacy struct {
			GlobalProcessScan bool `json:"global_process_scan"`
			CommandLineRead   bool `json:"command_line_read"`
			EnvironmentRead   bool `json:"environment_read"`
			QueueContentRead  bool `json:"queue_content_read"`
		} `json:"privacy"`
	}
	if err := json.Unmarshal(body, &receipt); err != nil {
		t.Fatalf("invalid benchmark receipt: %v\n%s", err, body)
	}
	if receipt.Profile != "FELIX_WATCH_FW_0401_RESOURCE_BENCHMARK_V1" || receipt.Status != "MEASUREMENT_ONLY_NOT_PHYSICAL_ACCEPTANCE" {
		t.Fatalf("unexpected receipt identity: %#v", receipt)
	}
	if receipt.PID != os.Getpid() || receipt.Samples != 1 {
		t.Fatalf("unexpected receipt scope: %#v", receipt)
	}
	var processIdentity struct {
		ProcessStartTicks uint64 `json:"process_start_ticks"`
	}
	if err := json.Unmarshal(body, &processIdentity); err != nil {
		t.Fatalf("invalid process identity field: %v", err)
	}
	if processIdentity.ProcessStartTicks == 0 {
		t.Fatal("benchmark receipt must bind samples to the process start time")
	}
	if receipt.Privacy.GlobalProcessScan || receipt.Privacy.CommandLineRead || receipt.Privacy.EnvironmentRead || receipt.Privacy.QueueContentRead {
		t.Fatalf("benchmark privacy boundary weakened: %#v", receipt.Privacy)
	}
	if err := exec.Command("sh", scriptPath,
		"--pid", strconv.Itoa(os.Getpid()),
		"--duration-seconds", "1",
		"--sample-seconds", "1",
		"--output", outputPath,
	).Run(); err == nil {
		t.Fatal("benchmark harness must not overwrite an existing receipt")
	}
	invalidOutputPath := filepath.Join(t.TempDir(), "invalid-receipt.json")
	if err := exec.Command("sh", scriptPath,
		"--pid", strconv.Itoa(os.Getpid()),
		"--duration-seconds", "1",
		"--sample-seconds", "2",
		"--output", invalidOutputPath,
	).Run(); err == nil {
		t.Fatal("benchmark harness must reject an interval longer than its duration")
	}
	if _, err := os.Stat(invalidOutputPath); !os.IsNotExist(err) {
		t.Fatalf("invalid benchmark must not create a receipt: %v", err)
	}
}
