package util

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// RotateWriter is an io.WriteCloser that writes to a date-stamped file
// in dir, rotates daily, maintains a stable symlink "<prefix>" pointing
// at the current file, and prunes files older than MaxAgeDays.
//
// File naming: "<prefix>.YYYYMMDD" (the symlink is just "<prefix>").
// A non-positive MaxAgeDays disables pruning.
type RotateWriter struct {
	dir        string
	prefix     string
	maxAgeDays int

	mu   sync.Mutex
	file *os.File
	date string

	now func() time.Time // overridable for tests
}

// NewRotateWriter creates a RotateWriter that writes to dir using the given
// file-name prefix. The directory is created if it does not exist.
// maxAgeDays <= 0 disables pruning of old files.
func NewRotateWriter(dir, prefix string, maxAgeDays int) (*RotateWriter, error) {
	if dir == "" {
		return nil, fmt.Errorf("rotate writer: dir is empty")
	}
	if prefix == "" {
		return nil, fmt.Errorf("rotate writer: prefix is empty")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("rotate writer: mkdir %s: %w", dir, err)
	}
	return &RotateWriter{
		dir:        dir,
		prefix:     prefix,
		maxAgeDays: maxAgeDays,
		now:        time.Now,
	}, nil
}

// Write writes p to the current day's log file, rotating if the date changed.
func (w *RotateWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	today := w.now().Format("20060102")
	if today != w.date {
		if w.file != nil {
			_ = w.file.Close()
			w.file = nil
		}
		name := w.prefix + "." + today
		f, err := os.OpenFile(filepath.Join(w.dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			w.date = ""
			return 0, fmt.Errorf("rotate writer: open: %w", err)
		}
		w.file = f
		w.date = today
		link := filepath.Join(w.dir, w.prefix)
		_ = os.Remove(link)
		_ = os.Symlink(name, link)
		w.clean()
	}
	if w.file == nil {
		return 0, fmt.Errorf("rotate writer: file not open")
	}
	return w.file.Write(p)
}

// Close closes the underlying file (if open). Subsequent Writes will
// reopen a fresh file.
func (w *RotateWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

func (w *RotateWriter) clean() {
	if w.maxAgeDays <= 0 {
		return
	}
	cutoff := w.now().AddDate(0, 0, -w.maxAgeDays)
	entries, _ := os.ReadDir(w.dir)
	filePrefix := w.prefix + "."
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), filePrefix) {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		_ = os.Remove(filepath.Join(w.dir, e.Name()))
	}
}
