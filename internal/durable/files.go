// Package durable owns crash-safe, private state files.
package durable

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func WriteChecked(path string, data []byte) error {
	hash := sha256.Sum256(data)
	raw, e := json.Marshal(struct {
		SHA256 string
		Data   json.RawMessage
	}{hex.EncodeToString(hash[:]), data})
	if e != nil {
		return e
	}
	return Write(path, raw)
}
func ReadChecked(path string) ([]byte, error) {
	raw, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	if len(raw) > 128<<10 {
		return nil, errors.New("state_integrity")
	}
	var envelope struct {
		SHA256 string
		Data   json.RawMessage
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return nil, errors.New("state_integrity")
	}
	hash := sha256.Sum256(envelope.Data)
	if envelope.SHA256 != hex.EncodeToString(hash[:]) {
		return nil, errors.New("state_integrity")
	}
	return envelope.Data, nil
}

func SyncDir(dir string) error {
	f, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func Write(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, e := os.CreateTemp(dir, ".pending-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	return SyncDir(dir)
}
func Remove(path string) error {
	if e := os.Remove(path); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return SyncDir(filepath.Dir(path))
}
func Directory(dir string) error {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	return os.Chmod(dir, 0700)
}

// ErrLocked means another process holds the state directory.
var ErrLocked = errors.New("state_directory_locked")

// Lock prevents two processes from sharing one identity and buffer.
func Lock(dir string) (*os.File, error) {
	if e := Directory(dir); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		if errors.Is(e, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, e
	}
	return f, nil
}
