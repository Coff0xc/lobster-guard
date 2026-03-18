//go:build !gen_assets

// assets_stub.go — open-source fallback when assets_gen.go is not present.
// All functions return empty results. Use `extract` command with external templates instead.
package assets

import (
	"fmt"
	"io/fs"
	"time"
)

type file struct {
	Path string
	Data string
}

var embeddedFiles []file

func List() []string { return nil }

func ReadFile(name string) ([]byte, error) {
	return nil, fmt.Errorf("embedded asset %q not available (open-source build)", name)
}

func ListDir(dir string) []string { return nil }

type memFS struct{ root string }

func FS(root string) fs.FS { return &memFS{root: root} }

func (m *memFS) Open(name string) (fs.File, error) {
	return nil, fmt.Errorf("embedded asset %q not available (open-source build)", name)
}

type memFile struct {
	name string
	data []byte
	off  int
}

func (f *memFile) Stat() (fs.FileInfo, error) { return f, nil }
func (f *memFile) Read(b []byte) (int, error)  { return 0, fmt.Errorf("no data") }
func (f *memFile) Close() error                { return nil }
func (f *memFile) Name() string                { return f.name }
func (f *memFile) Size() int64                 { return 0 }
func (f *memFile) Mode() fs.FileMode           { return 0444 }
func (f *memFile) ModTime() time.Time          { return time.Time{} }
func (f *memFile) IsDir() bool                 { return false }
func (f *memFile) Sys() any                    { return nil }
