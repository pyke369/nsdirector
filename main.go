package main

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/pyke369/golang-support/uconfig"
)

var (
	progname  = "nsdirector"
	version   = "1.4.2"
	retention = 5
)

func usage(status int) int {
	fmt.Fprintf(os.Stderr,
		"usage: %s <action> [parameters...]\n\n"+
			"help\n"+
			"  print this help message and exit\n\n"+
			"version\n"+
			"  print the program version and exit\n\n"+
			"pack <source> <target> [<retention>]\n"+
			"  pack <source> configuration directory into <target> archive\n"+
			"  (keep <retention> older versions, default %d)\n\n"+
			"fetch <remote> <target> [<retention>]\n"+
			"  synchronize <remote> configuration into <target> directory \n"+
			"  (keep <retention> older versions, default %d)\n\n"+
			"backend <configuration>\n"+
			"  start as a PowerDNS pipe backend\n\n"+
			"dump <configuration>\n"+
			"  validate and dump configuration in text/json format\n",
		progname, retention, retention,
	)
	return status
}

func main() {
	if len(os.Args) < 2 {
		os.Exit(usage(1))
	}
	switch strings.ToLower(os.Args[1]) {
	case "help":
		os.Exit(usage(0))

	case "version":
		fmt.Printf("%s/%s\n", progname, version)
		os.Exit(0)

	case "pack":
		if len(os.Args) < 4 {
			fmt.Fprintf(os.Stderr, "missing parameters for pack action - try using \"%s help\"\n", os.Args[1], progname)
			os.Exit(1)
		}
		if len(os.Args) > 4 {
			retention, _ = strconv.Atoi(os.Args[4])
			retention = int(math.Min(10, math.Max(0, float64(retention))))
		}
		if err := pack(os.Args[2], os.Args[3], retention); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}

	case "fetch", "sync":
		if len(os.Args) < 4 {
			fmt.Fprintf(os.Stderr, "missing parameters for fetch action - try using \"%s help\"\n", os.Args[1], progname)
			os.Exit(1)
		}
		if len(os.Args) > 4 {
			retention, _ = strconv.Atoi(os.Args[4])
			retention = int(math.Min(10, math.Max(0, float64(retention))))
		}
		if err := fetch(os.Args[2], os.Args[3], retention); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}

	case "backend":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "missing configuration parameter for backend action - try using \"%s help\"\n", os.Args[1], progname)
			os.Exit(1)
		}
		backend(os.Args[2])

	case "dump":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "missing configuration parameter for dump action - try using \"%s help\"\n", os.Args[1], progname)
			os.Exit(1)
		}
		if config, err := uconfig.New(os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		} else {
			fmt.Printf("%s\n", config)
		}

	default:
		fmt.Fprintf(os.Stderr, "unknown action \"%s\" - try using \"%s help\"\n", os.Args[1], progname)
		os.Exit(1)
	}
}
