package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/pyke369/golang-support/uconfig"
)

func fetch(remote, target string, retention int) error {
	lsum := ""
	if content, err := ioutil.ReadFile(target + "/.sum"); err == nil && len(content) >= 40 {
		lsum = string(content[:40])
	}

	client := &http.Client{Timeout: 30 * time.Minute}
	if response, err := client.Get(remote + ".sum"); err == nil {
		if content, err := ioutil.ReadAll(response.Body); err != nil {
			return err
		} else {
			response.Body.Close()
			if response.StatusCode != 200 || len(content) < 40 {
				return fmt.Errorf("cannot check remote checksum")
			}

			if rsum := string(content[:40]); lsum != rsum {
				os.RemoveAll(target + "_")
				if err := os.MkdirAll(target+"_", 0755); err != nil {
					return err
				}
				if err := ioutil.WriteFile(target+"_/.sum", []byte(rsum+"\n"), 0644); err != nil {
					return err
				}

				if response, err := client.Get(remote + ".pack"); err == nil {
					if content, err := ioutil.ReadAll(response.Body); err != nil {
						return err
					} else {
						response.Body.Close()
						if fmt.Sprintf("%x", sha1.Sum(content)) != rsum {
							return fmt.Errorf("invalid checksum")
						}

						uncompressor, _ := gzip.NewReader(bytes.NewReader(content))
						reader := tar.NewReader(uncompressor)
						for {
							if header, err := reader.Next(); err == io.EOF {
								break
							} else {
								if err != nil {
									return err
								}
								if header.FileInfo().Mode().IsRegular() {
									if err := os.MkdirAll(filepath.Dir(target+"_/"+header.Name), 0755); err != nil {
										return err
									}
									if handle, err := os.OpenFile(target+"_/"+header.Name, os.O_WRONLY|os.O_CREATE, 0644); err != nil {
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

						if _, err := uconfig.New(fmt.Sprintf("domains\n{\n{{<%s_/*.conf}}\n}\n", target), true); err != nil {
							return fmt.Errorf("invalid configuration (%v)", err)
						}
						if info, err := os.Stat(target); err == nil && info.Mode().IsDir() {
							os.Rename(target, fmt.Sprintf("%s.%d", target, time.Now().Unix()))
						}
						os.Rename(target+"_", target)
						if archives, _ := filepath.Glob(target + ".*"); len(archives) > retention {
							for index := 0; index < len(archives)-retention; index++ {
								os.RemoveAll(archives[index])
							}
						}
					}
				} else {
					return err
				}
			}
		}
	} else {
		return err
	}

	return nil
}
