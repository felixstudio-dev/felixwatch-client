package agent

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
)

type Queue struct {
	Path     string
	MaxBytes int64
}

type QueueStats struct {
	Bytes       int64
	MaxBytes    int64
	UsedPercent float64
}

func (q Queue) Stats() (QueueStats, error) {
	if q.MaxBytes <= 0 {
		return QueueStats{}, errors.New("queue max bytes must be positive")
	}
	stats := QueueStats{MaxBytes: q.MaxBytes}
	info, err := os.Stat(q.Path)
	if errors.Is(err, os.ErrNotExist) {
		return stats, nil
	}
	if err != nil {
		return QueueStats{}, err
	}
	if !info.Mode().IsRegular() {
		return QueueStats{}, errors.New("queue path is not a regular file")
	}
	stats.Bytes = info.Size()
	stats.UsedPercent = float64(stats.Bytes) / float64(stats.MaxBytes) * 100
	if stats.UsedPercent > 100 {
		stats.UsedPercent = 100
	}
	return stats, nil
}

func (q Queue) Enqueue(payload []byte) error {
	if q.MaxBytes <= 0 {
		return errors.New("queue max bytes must be positive")
	}
	if err := os.MkdirAll(filepath.Dir(q.Path), 0o700); err != nil {
		return err
	}
	existing, _ := os.ReadFile(q.Path)
	entry := append(append([]byte(nil), payload...), '\n')
	combined := append(existing, entry...)
	if int64(len(combined)) > q.MaxBytes {
		lines := bytes.Split(combined, []byte{'\n'})
		var kept [][]byte
		var size int64
		for i := len(lines) - 1; i >= 0; i-- {
			if len(lines[i]) == 0 {
				continue
			}
			need := int64(len(lines[i]) + 1)
			if size+need > q.MaxBytes {
				break
			}
			kept = append(kept, lines[i])
			size += need
		}
		var out bytes.Buffer
		for i := len(kept) - 1; i >= 0; i-- {
			out.Write(kept[i])
			out.WriteByte('\n')
		}
		combined = out.Bytes()
	}
	return os.WriteFile(q.Path, combined, 0o600)
}

func (q Queue) Drain(send func([]byte) error) error {
	f, err := os.Open(q.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var remaining [][]byte
	failed := false
	s := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	s.Buffer(buf, 256*1024)
	for s.Scan() {
		line := append([]byte(nil), s.Bytes()...)
		if len(line) == 0 {
			continue
		}
		if failed {
			remaining = append(remaining, line)
			continue
		}
		if err := send(line); err != nil {
			failed = true
			remaining = append(remaining, line)
		}
	}
	if err := s.Err(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	var out bytes.Buffer
	for _, line := range remaining {
		out.Write(line)
		out.WriteByte('\n')
	}
	if len(remaining) == 0 {
		if err := os.Remove(q.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return os.WriteFile(q.Path, out.Bytes(), 0o600)
}
