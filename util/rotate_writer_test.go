package util

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestRotateWriter_WriteCreatesFileAndSymlink(t *testing.T) {
	dir := t.TempDir()
	w, err := NewRotateWriter(dir, "test.log", 0)
	if err != nil {
		t.Fatalf("NewRotateWriter: %v", err)
	}
	defer func() { _ = w.Close() }()

	fixed := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	w.now = func() time.Time { return fixed }

	if _, err := w.Write([]byte("hello\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, "test.log.20260610"))
	if err != nil {
		t.Fatalf("read dated file: %v", err)
	}
	if string(got) != "hello\n" {
		t.Errorf("file content = %q, want %q", got, "hello\n")
	}

	link, err := os.Readlink(filepath.Join(dir, "test.log"))
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if link != "test.log.20260610" {
		t.Errorf("symlink = %q, want %q", link, "test.log.20260610")
	}
}

func TestRotateWriter_DateRollover(t *testing.T) {
	dir := t.TempDir()
	w, err := NewRotateWriter(dir, "app.log", 0)
	if err != nil {
		t.Fatalf("NewRotateWriter: %v", err)
	}
	defer func() { _ = w.Close() }()

	day1 := time.Date(2026, 6, 10, 23, 59, 0, 0, time.UTC)
	day2 := day1.Add(2 * time.Minute)

	w.now = func() time.Time { return day1 }
	if _, err := w.Write([]byte("day1\n")); err != nil {
		t.Fatalf("Write day1: %v", err)
	}
	w.now = func() time.Time { return day2 }
	if _, err := w.Write([]byte("day2\n")); err != nil {
		t.Fatalf("Write day2: %v", err)
	}

	d1, err := os.ReadFile(filepath.Join(dir, "app.log.20260610"))
	if err != nil {
		t.Fatalf("read day1: %v", err)
	}
	if string(d1) != "day1\n" {
		t.Errorf("day1 file = %q, want %q", d1, "day1\n")
	}

	d2, err := os.ReadFile(filepath.Join(dir, "app.log.20260611"))
	if err != nil {
		t.Fatalf("read day2: %v", err)
	}
	if string(d2) != "day2\n" {
		t.Errorf("day2 file = %q, want %q", d2, "day2\n")
	}

	link, err := os.Readlink(filepath.Join(dir, "app.log"))
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if link != "app.log.20260611" {
		t.Errorf("symlink after rollover = %q, want %q", link, "app.log.20260611")
	}
}

func TestRotateWriter_PrunesOldFiles(t *testing.T) {
	dir := t.TempDir()

	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)

	old := filepath.Join(dir, "svc.log.20260101")
	if err := os.WriteFile(old, []byte("old"), 0o644); err != nil {
		t.Fatalf("write old: %v", err)
	}
	oldTime := now.AddDate(0, 0, -30)
	if err := os.Chtimes(old, oldTime, oldTime); err != nil {
		t.Fatalf("chtimes old: %v", err)
	}

	recent := filepath.Join(dir, "svc.log.20260608")
	if err := os.WriteFile(recent, []byte("recent"), 0o644); err != nil {
		t.Fatalf("write recent: %v", err)
	}
	recentTime := now.AddDate(0, 0, -2)
	if err := os.Chtimes(recent, recentTime, recentTime); err != nil {
		t.Fatalf("chtimes recent: %v", err)
	}

	unrelated := filepath.Join(dir, "other.log.20260101")
	if err := os.WriteFile(unrelated, []byte("other"), 0o644); err != nil {
		t.Fatalf("write unrelated: %v", err)
	}
	if err := os.Chtimes(unrelated, oldTime, oldTime); err != nil {
		t.Fatalf("chtimes unrelated: %v", err)
	}

	w, err := NewRotateWriter(dir, "svc.log", 7)
	if err != nil {
		t.Fatalf("NewRotateWriter: %v", err)
	}
	defer func() { _ = w.Close() }()
	w.now = func() time.Time { return now }

	if _, err := w.Write([]byte("new\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("old file should be pruned, got err=%v", err)
	}
	if _, err := os.Stat(recent); err != nil {
		t.Errorf("recent file should be kept: %v", err)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Errorf("unrelated prefix should be kept: %v", err)
	}
}

func TestRotateWriter_MaxAgeZeroNoPruning(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "k.log.20200101")
	if err := os.WriteFile(old, []byte("ancient"), 0o644); err != nil {
		t.Fatalf("write old: %v", err)
	}
	oldTime := time.Now().AddDate(-5, 0, 0)
	if err := os.Chtimes(old, oldTime, oldTime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	w, err := NewRotateWriter(dir, "k.log", 0)
	if err != nil {
		t.Fatalf("NewRotateWriter: %v", err)
	}
	defer func() { _ = w.Close() }()

	if _, err := w.Write([]byte("hi\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if _, err := os.Stat(old); err != nil {
		t.Errorf("with maxAgeDays=0 old file must be kept: %v", err)
	}
}

func TestRotateWriter_ConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	w, err := NewRotateWriter(dir, "c.log", 0)
	if err != nil {
		t.Fatalf("NewRotateWriter: %v", err)
	}
	defer func() { _ = w.Close() }()

	const goroutines = 16
	const perG = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			payload := []byte("x\n")
			for j := 0; j < perG; j++ {
				if _, err := w.Write(payload); err != nil {
					t.Errorf("Write: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	today := time.Now().Format("20060102")
	data, err := os.ReadFile(filepath.Join(dir, "c.log."+today))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if want := goroutines * perG * len("x\n"); len(data) != want {
		t.Errorf("file size = %d, want %d", len(data), want)
	}
}

func TestRotateWriter_RejectsEmptyArgs(t *testing.T) {
	if _, err := NewRotateWriter("", "p", 0); err == nil {
		t.Error("expected error for empty dir")
	}
	if _, err := NewRotateWriter(t.TempDir(), "", 0); err == nil {
		t.Error("expected error for empty prefix")
	}
}
