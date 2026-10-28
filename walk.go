package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/ulikunitz/xz"
)

const (
	maxFileSize = 1 << 30
	maxDepth    = 6
)

// visit receives every regular file, with archive members named outer!inner.
type visit func(name string, data []byte)

func walkPath(root string, fn visit) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return open(p, data, 0, fn)
	})
}

func open(name string, data []byte, depth int, fn visit) error {
	if depth > maxDepth {
		fn(name, data)
		return nil
	}
	switch {
	case bytes.HasPrefix(data, []byte("PK\x03\x04")):
		return openZip(name, data, depth, fn)
	case bytes.HasPrefix(data, []byte{0x1f, 0x8b}):
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return openStream(name, r, depth, fn)
	case bytes.HasPrefix(data, []byte{0xfd, '7', 'z', 'X', 'Z', 0}):
		r, err := xz.NewReader(bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return openStream(name, r, depth, fn)
	case len(data) > 262 && bytes.Equal(data[257:262], []byte("ustar")):
		return openTar(name, data, depth, fn)
	}
	fn(name, data)
	return nil
}

func openStream(name string, r io.Reader, depth int, fn visit) error {
	data, err := io.ReadAll(io.LimitReader(r, maxFileSize))
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return open(name, data, depth+1, fn)
}

func openTar(name string, data []byte, depth int, fn visit) error {
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		member, err := io.ReadAll(io.LimitReader(tr, maxFileSize))
		if err != nil {
			return fmt.Errorf("%s!%s: %w", name, h.Name, err)
		}
		if err := open(name+"!"+h.Name, member, depth+1, fn); err != nil {
			return err
		}
	}
}

func openZip(name string, data []byte, depth int, fn visit) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("%s!%s: %w", name, f.Name, err)
		}
		member, err := io.ReadAll(io.LimitReader(rc, maxFileSize))
		rc.Close()
		if err != nil {
			return fmt.Errorf("%s!%s: %w", name, f.Name, err)
		}
		if err := open(name+"!"+f.Name, member, depth+1, fn); err != nil {
			return err
		}
	}
	return nil
}
