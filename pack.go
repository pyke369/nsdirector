package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha1"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pyke369/golang-support/uconfig"
)

func pack(root, target string, retention int) error {
	if _, err := uconfig.New(fmt.Sprintf("domains\n{\n{{<%s/*.conf}}\n}\n", root), true); err != nil {
		return fmt.Errorf("invalid configuration (%v)", err)
	}

	if handle, err := os.Create(target + ".pack_"); err != nil {
		return err
	} else {
		compressor, _ := gzip.NewWriterLevel(handle, 9)
		writer := tar.NewWriter(compressor)
		if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if info.Mode().IsRegular() {
				if content, err := ioutil.ReadFile(path); err != nil {
					return err
				} else {
					writer.WriteHeader(&tar.Header{
						Name:    strings.TrimPrefix(path, root+"/"),
						Mode:    0644,
						ModTime: info.ModTime(),
						Size:    int64(len(content)),
					})
					writer.Write(content)
				}
			}
			return nil
		}); err != nil {
			os.Remove(target + ".pack_")
			return err
		}
		writer.Close()
		compressor.Close()
		handle.Close()

		if content, err := ioutil.ReadFile(target + ".pack_"); err != nil {
			os.Remove(target + ".pack_")
			return err
		} else {
			if err := ioutil.WriteFile(target+".sum_", []byte(fmt.Sprintf("%x\n", sha1.Sum(content))), 0644); err != nil {
				os.Remove(target + ".pack_")
				return err
			}
		}

		if content, err := ioutil.ReadFile(target + ".pack"); err == nil {
			ioutil.WriteFile(fmt.Sprintf("%s.pack.%d", target, time.Now().Unix()), content, 0644)
		}
		if err := os.Rename(target+".pack_", target+".pack"); err != nil {
			return err
		} else {
			os.Rename(target+".sum_", target+".sum")
		}
		if archives, _ := filepath.Glob(target + ".pack.*"); len(archives) > retention {
			for index := 0; index < len(archives)-retention; index++ {
				os.Remove(archives[index])
			}
		}
	}
	return nil
}
