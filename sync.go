package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/pyke369/golang-support/uconfig"
	"github.com/pyke369/golang-support/ustr"
)

func Sync(remote, target string, retention int) error {
	lsum := ""
	if content, err := os.ReadFile(filepath.Join(target, ".sum")); err == nil && len(content) >= 40 {
		lsum = string(content[:40])
	}

	client := &http.Client{Timeout: 30 * time.Second}
	if response, err := client.Get(remote + ".sum"); err == nil {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()

		if response.StatusCode != 200 || len(body) < 40 {
			return errors.New("cannot check remote checksum")
		}

		if rsum := string(body[:40]); lsum != rsum {
			os.RemoveAll(target + "_")
			if err := os.MkdirAll(target+"_", 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(target+"_", ".sum"), []byte(rsum+"\n'"), 0o644); err != nil {
				return err
			}

			if response, err := client.Get(remote + ".pack"); err == nil {
				body, _ := io.ReadAll(response.Body)
				response.Body.Close()

				sum := sha1.Sum(body)
				if ustr.Hex(sum[:]) != rsum {
					return errors.New("invalid checksum")
				}

				uncompressor, _ := gzip.NewReader(bytes.NewReader(body))
				reader := tar.NewReader(uncompressor)
				for {
					if header, err := reader.Next(); err == io.EOF {
						break

					} else {
						if err != nil {
							return err
						}
						if header.FileInfo().Mode().IsRegular() {
							if err := os.MkdirAll(filepath.Dir(filepath.Join(target+"_", header.Name)), 0o755); err != nil {
								return err
							}
							if handle, err := os.OpenFile(filepath.Join(target+"_", header.Name), os.O_WRONLY|os.O_CREATE, 0o644); err != nil {
								return err

							} else {
								if _, err := io.Copy(handle, reader); err != nil {
									return err
								}
								handle.Close()
							}
						}
					}
				}
				uncompressor.Close()

				if _, err := uconfig.New("domains {\n<<~ "+filepath.Join(target+"_", "*.conf")+">>\n}\n", map[string]any{"inline": true}); err != nil {
					return err
				}
				if info, err := os.Stat(target); err == nil && info.Mode().IsDir() {
					os.Rename(target, target+"."+strconv.Itoa(int(time.Now().Unix())))
				}
				os.Rename(target+"_", target)
				if archives, _ := filepath.Glob(target + ".*"); len(archives) > retention {
					for index := 0; index < len(archives)-retention; index++ {
						os.RemoveAll(archives[index])
					}
				}

			} else {
				return err
			}
		}

	} else {
		return err
	}

	return nil
}
