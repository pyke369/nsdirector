package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pyke369/golang-support/uconfig"
	"github.com/pyke369/golang-support/ustr"
)

func Pack(root, target string, retention int) error {
	if _, err := uconfig.New("domains\n{\n<<~"+filepath.Join(root, "*.conf")+">>\n}\n", map[string]any{"inline": true}); err != nil {
		return err
	}

	handle, err := os.Create(target + ".pack_")
	if err != nil {
		return err
	}

	compressor, _ := gzip.NewWriterLevel(handle, 9)
	writer := tar.NewWriter(compressor)
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if info.Mode().IsRegular() {
			if content, err := os.ReadFile(path); err != nil {
				return err

			} else {
				writer.WriteHeader(&tar.Header{
					Name:    strings.TrimPrefix(path, root+"/"),
					Mode:    0o644,
					ModTime: info.ModTime(),
					Size:    int64(len(content)),
				})
				writer.Write(content)
			}
		}

		return nil
	}); err != nil {
		handle.Close()
		os.Remove(target + ".pack_")
		return err
	}
	writer.Close()
	compressor.Close()
	handle.Close()

	content, err := os.ReadFile(target + ".pack_")
	if err != nil {
		os.Remove(target + ".pack_")
		return err
	}
	sum := sha1.Sum(content)
	if err := os.WriteFile(target+".sum_", []byte(ustr.Hex(sum[:])+"\n"), 0o644); err != nil {
		os.Remove(target + ".pack_")
		return err
	}

	if sum1, err := os.ReadFile(target + ".sum_"); err == nil {
		if sum2, err := os.ReadFile(target + ".sum"); err == nil {
			if bytes.Equal(sum1, sum2) {
				os.Remove(target + ".pack_")
				os.Remove(target + ".sum_")
				return nil
			}
		}
	}

	if content, err := os.ReadFile(target + ".pack"); err == nil {
		os.WriteFile(target+".pack."+strconv.Itoa(int(time.Now().Unix())), content, 0o644)
	}
	if err := os.Rename(target+".pack_", target+".pack"); err != nil {
		return err
	}
	os.Rename(target+".sum_", target+".sum")

	if archives, _ := filepath.Glob(target + ".pack.*"); len(archives) > retention {
		for index := 0; index < len(archives)-retention; index++ {
			os.Remove(archives[index])
		}
	}

	return nil
}
