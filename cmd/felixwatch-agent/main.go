package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/felixstudio-dev/felixwatch-client/internal/agent"
	"github.com/felixstudio-dev/felixwatch-client/internal/config"
	"github.com/felixstudio-dev/felixwatch-client/internal/protocol"
)

const version = "0.1.0-foundation"

func main() {
	configPath := flag.String("config", "/etc/felixwatch/agent.json", "agent configuration path")
	once := flag.Bool("once", false, "collect and send one heartbeat, then exit")
	flag.Parse()

	logger := log.New(os.Stderr, "felixwatch-agent ", log.LstdFlags|log.LUTC)
	var cfg config.AgentConfig
	if err := config.Load(*configPath, &cfg); err != nil {
		logger.Fatalf("configuration error: error_class=%T", err)
	}
	if err := cfg.NormalizeAndValidate(); err != nil {
		logger.Fatalf("configuration validation error: error_class=%T", err)
	}
	secret, err := config.EnvRequired(cfg.SecretEnv)
	if err != nil {
		logger.Fatalf("secret loading error: error_class=%T", err)
	}
	sender := agent.NewSender(cfg.CollectorURL, cfg.AgentID, []byte(secret))
	queue := agent.Queue{Path: cfg.QueuePath, MaxBytes: cfg.QueueMaxBytes}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var seq atomic.Uint64
	seq.Store(uint64(time.Now().UnixNano()))

	logQueuePressure := func() {
		stats, err := queue.Stats()
		if err != nil {
			logger.Printf("queue pressure measurement failed: error_class=%T", err)
			return
		}
		if stats.Bytes > 0 {
			logger.Printf("queue pressure: bytes=%d max_bytes=%d utilization_pct=%.2f", stats.Bytes, stats.MaxBytes, stats.UsedPercent)
		}
	}

	run := func() {
		if err := queue.Drain(func(payload []byte) error { return sender.Send(ctx, payload) }); err != nil {
			logger.Printf("queue drain failed: error_class=%T", err)
		}
		logQueuePressure()
		metrics, err := agent.CollectMetrics()
		if err != nil {
			logger.Printf("metric collection failed: error_class=%T", err)
			return
		}
		hb := protocol.Heartbeat{
			ProtocolVersion:  protocol.ProtocolVersion,
			AgentID:          cfg.AgentID,
			CustomerID:       cfg.CustomerID,
			InfrastructureID: cfg.InfrastructureID,
			ServerID:         cfg.ServerID,
			ObservedAtUnix:   time.Now().Unix(),
			Sequence:         seq.Add(1),
			AgentVersion:     version,
			Metrics:          metrics,
			Services:         agent.CheckServices(cfg.Services),
			Sites:            agent.CheckSites(ctx, cfg.Sites),
		}
		body, err := json.Marshal(hb)
		if err != nil {
			logger.Printf("heartbeat encoding failed: error_class=%T", err)
			return
		}
		if err := sender.Send(ctx, body); err != nil {
			if qerr := queue.Enqueue(body); qerr != nil {
				logger.Printf("heartbeat send failed and bounded queue write failed: send_error_class=%T queue_error_class=%T", err, qerr)
				return
			}
			logger.Printf("heartbeat send failed; evidence queued within configured bound: error_class=%T", err)
			logQueuePressure()
		}
	}

	run()
	if *once {
		return
	}
	ticker := time.NewTicker(time.Duration(cfg.IntervalSeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "felixwatch-agent stopped")
			return
		case <-ticker.C:
			run()
		}
	}
}
