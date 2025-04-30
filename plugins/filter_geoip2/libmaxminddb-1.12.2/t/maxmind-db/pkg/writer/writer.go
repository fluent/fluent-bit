// Package writer defines database writers responsible
// for generating test mmdb files.
package writer

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/maxmind/mmdbwriter"
)

var ipSample = []string{
	"::1.1.1.0/120",
	"::2.2.0.0/112",
	"::3.0.0.0/104",
	"::4.5.6.7/128",
	"abcd::/64",
	"1000::1234:0000/112",
}

// Writer is responsible for writing test mmdb databases
// based on the provided data sources.
type Writer struct {
	source string
	target string
}

// New initializes a new test database writer struct.
func New(source, target string) (*Writer, error) {
	s := filepath.Clean(source)
	if _, err := os.Stat(s); errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("source directory does not exist: %w", err)
	}

	t := filepath.Clean(target)
	//nolint:gosec // not security sensitive.
	if err := os.MkdirAll(t, os.ModePerm); err != nil {
		return nil, fmt.Errorf("creating target directory: %w", err)
	}

	return &Writer{
		source: s,
		target: t,
	}, nil
}

func (w *Writer) write(dbWriter *mmdbwriter.Tree, fileName string) error {
	outputFile, err := os.Create(filepath.Clean(filepath.Join(w.target, fileName)))
	if err != nil {
		return fmt.Errorf("creating mmdb file: %w", err)
	}
	defer outputFile.Close()

	if _, err := dbWriter.WriteTo(outputFile); err != nil {
		return fmt.Errorf("writing mmdb file: %w", err)
	}
	return nil
}
