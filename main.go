package main

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pyke369/golang-support/uconfig"
)

var (
	PROGNAME = "nsdirector"
	PROGVER  = "2.1.0"
)

func usage(status int) int {
	os.Stderr.WriteString(
		"usage: " + filepath.Base(os.Args[0]) + ` <action> [parameter...]

help
  print this help message and exit

version
  print the program version and exit

pack <source> <target> [<retention>]
  pack <source> configuration directory into <target> archive
  (keep <retention> older versions, default 5)

sync <remote> <target> [<retention>]
  synchronize <remote> configuration into <target> directory
  (keep <retention> older versions, default 5)

backend <configuration>
  start as a PowerDNS http backend

dump <configuration>
  validate and dump configuration in json format
`)

	return status
}

func main() {
	retention := 5
	if len(os.Args) < 2 {
		os.Exit(usage(1))
	}

	switch strings.ToLower(os.Args[1]) {
	case "help":
		os.Exit(usage(0))

	case "version":
		os.Stdout.WriteString(PROGNAME + "/" + PROGVER + "\n")
		os.Exit(0)

	case "pack":
		if len(os.Args) < 4 {
			os.Stderr.WriteString("missing parameter for pack action - aborting\n")
			os.Exit(1)
		}
		if len(os.Args) > 4 {
			retention, _ = strconv.Atoi(os.Args[4])
			retention = int(math.Min(10, math.Max(0, float64(retention))))
		}
		if err := Pack(os.Args[2], os.Args[3], retention); err != nil {
			os.Stderr.WriteString(err.Error() + " - aborting\n")
			os.Exit(1)
		}

	case "sync":
		if len(os.Args) < 4 {
			os.Stderr.WriteString("missing parameter for sync action - aborting\n")
			os.Exit(1)
		}
		if len(os.Args) > 4 {
			retention, _ = strconv.Atoi(os.Args[4])
			retention = int(math.Min(10, math.Max(0, float64(retention))))
		}
		if err := Sync(os.Args[2], os.Args[3], retention); err != nil {
			os.Stderr.WriteString(err.Error() + " - aborting\n")
			os.Exit(1)
		}

	case "backend":
		if len(os.Args) < 3 {
			os.Stderr.WriteString("missing parameter for backend action - aborting\n")
			os.Exit(1)
		}
		if err := Backend(os.Args[2]); err != nil {
			os.Stderr.WriteString(err.Error() + " - aborting\n")
			os.Exit(1)
		}

	case "dump":
		if len(os.Args) < 3 {
			os.Stderr.WriteString("missing parameter for dump action - aborting\n")
			os.Exit(1)
		}
		config, err := uconfig.New(os.Args[2])
		if err != nil {
			os.Stderr.WriteString(err.Error() + " - aborting\n")
			os.Exit(1)
		}
		os.Stdout.WriteString(config.Dump() + "\n")

	default:
		os.Stderr.WriteString("unknow action '" + os.Args[1] + "' - aborting\n")
		os.Exit(1)
	}
}
