package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"time"
)

var rtypes = []string{"SOA", "NS", "A", "AAAA", "CNAME", "MX", "PTR", "SRV", "TXT"}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: bench <command>\n")
		os.Exit(1)
	}
	command := &exec.Cmd{Path: os.Args[1], Args: os.Args[1:]}
	if stdin, err := command.StdinPipe(); err == nil {
		if stdout, err := command.StdoutPipe(); err == nil {
			if err := command.Start(); err == nil {
				fmt.Printf("benching %v\n", os.Args[1:])
				time.Sleep(time.Second)
				reader, count, line, start, first := bufio.NewReader(stdout), 0, "", time.Now(), 0
				for {
					if count%1000 == 0 {
						line = "HELO\t3\n"
					} else {
						for {
							if first = (rand.Int() % 190) + 1; first != 10 && first != 172 && first != 192 {
								break
							}
						}
						remote := fmt.Sprintf("%d.%d.%d", first, rand.Int()%256, rand.Int()%256)
						line = fmt.Sprintf("Q\tentry1.domain1.com\tIN\t%s\t-1\t%s.%d\t0.0.0.0\t%s.0/24\n", rtypes[rand.Int()%len(rtypes)], remote, rand.Int()%256, remote)
					}
					fmt.Fprintf(stdin, line)
					// fmt.Printf("> " + line)
					for {
						if line, err := reader.ReadString('\n'); err != nil {
							fmt.Fprintf(os.Stderr, "%v - exiting\n", err)
							os.Exit(2)
						} else {
							line = strings.TrimSpace(line)
							// fmt.Printf("< %s\n", line)
							if strings.HasPrefix(line, "OK ") || line == "END" {
								break
							}
							if strings.HasPrefix(line, "FAIL") {
								fmt.Fprintf(os.Stderr, "benched program returned \"%s\" - exiting\n", line)
								os.Exit(2)
							}
						}
					}
					count++
					if count%1000 == 0 {
						fmt.Printf("\r%d %d/s    ", count, int((float64(count)*float64(time.Second))/float64(time.Now().Sub(start))))
					}
				}
			} else {
				fmt.Fprintf(os.Stderr, "%v - exiting\n", err)
			}
		} else {
			fmt.Fprintf(os.Stderr, "%v - exiting\n", err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "%v - exiting\n", err)
	}
}
