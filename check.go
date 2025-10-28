package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pyke369/golang-support/dynacert"
	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/uconfig"
	"github.com/pyke369/golang-support/ulog"
)

type CHECK struct {
	Last      int64  `json:"last"`
	State     string `json:"state"`
	Latency   int    `json:"latency"`
	Retries   int    `json:"retries,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Address   string `json:"address,omitempty"`
	latencies []int
	domain    string
}

type ADDRESS string

var (
	checkTransport *http.Transport
	checkMutex     sync.RWMutex
	checkEntries   = map[string]*CHECK{}
)

func init() {
	checkTransport = http.DefaultTransport.(*http.Transport).Clone()
	checkTransport.DisableKeepAlives = true
	checkTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	checkTransport.DialContext = func(context context.Context, network, address string) (net.Conn, error) {
		if target, ok := context.Value(ADDRESS("address")).(string); ok && target != "" {
			if _, port, err := net.SplitHostPort(address); err == nil {
				address = target + ":" + port
			}
		}
		return http.DefaultTransport.(*http.Transport).DialContext(context, network, address)
	}
}

func checkRun(logger *ulog.ULog, name, method, url, payload string, headers map[string]string, cstatus, cheaders, cpayload string, csize, retries int, timeout time.Duration) {
	var request *http.Request

	start, address, reason, pass, matcher := time.Now(), "", "", false, rcache.Get(`^(https?://)([^/]+)(.*)$`)
	if captures := matcher.FindStringSubmatch(url); captures != nil {
		if parts := strings.Split(captures[2], "|"); len(parts) == 2 {
			address, url = parts[0], matcher.ReplaceAllString(url, "${1}"+parts[1]+"${3}")
		}
	}
	if payload != "" {
		request, _ = http.NewRequest(method, url, bytes.NewBuffer([]byte(payload)))

	} else {
		request, _ = http.NewRequest(method, url, http.NoBody)
	}
	if request == nil {
		return
	}
	request = request.WithContext(context.WithValue(request.Context(), ADDRESS("address"), address))
	if request == nil {
		return
	}
	if _, exists := headers["User-Agent"]; !exists {
		request.Header.Add("User-Agent", PROGNAME+"/"+PROGVER)
	}
	if payload != "" {
		request.Header.Add("Content-Length", strconv.Itoa(len(payload)))
	}
	for key, value := range headers {
		request.Header.Add(key, value)
	}

	client := &http.Client{Transport: checkTransport, Timeout: timeout}
	if response, err := client.Do(request); err == nil {
		pass = true
		if cstatus != "" {
			if matcher := rcache.Get(cstatus); matcher != nil && !matcher.MatchString(strconv.Itoa(response.StatusCode)) {
				pass, reason = false, "invalid status code "+strconv.Itoa(response.StatusCode)
			}
		}
		if pass && cheaders != "" {
			if matcher := rcache.Get(cheaders); matcher != nil {
				pass, reason = false, "no matching header"
				for key := range response.Header {
					if matcher.MatchString(key + ": " + response.Header.Get(key)) {
						pass, reason = true, ""
						break
					}
				}
			}
		}
		if pass && (cpayload != "" || csize > 0) {
			if payload, err := io.ReadAll(response.Body); err == nil {
				if cpayload != "" {
					if matcher := rcache.Get(cpayload); matcher != nil && !matcher.Match(payload) {
						pass, reason = false, "no matching payload"
					}
				}
				if csize > 0 {
					if csize > len(payload) {
						pass, reason = false, "payload too small "+strconv.Itoa(len(payload))
					}
				}
			}
		}
		response.Body.Close()

	} else {
		pass, reason = false, err.Error()
	}

	checkMutex.RLock()
	entry, exists := checkEntries[name]
	checkMutex.RUnlock()
	if !exists {
		return
	}

	entry.Last, entry.Reason, entry.Address = time.Now().Unix(), reason, address
	entry.latencies = append(entry.latencies, int(time.Since(start)/time.Millisecond))
	if len(entry.latencies) > 5 {
		for index := 0; index < 5; index++ {
			entry.latencies[index] = entry.latencies[index+1]
		}
		entry.latencies = entry.latencies[:5]
	}
	latency, divider := 0, 0
	for index := 0; index < len(entry.latencies); index++ {
		latency += entry.latencies[index] * (index + 1)
		divider += (index + 1)
	}
	entry.Latency = latency / divider
	if entry.State == "up" {
		if pass {
			entry.Retries = 0

		} else {
			entry.Retries++
			logger.Info(map[string]any{
				"pid":     os.Getpid(),
				"scope":   "check",
				"event":   "fall",
				"domain":  entry.domain,
				"name":    name,
				"reason":  reason,
				"retries": strconv.Itoa(entry.Retries) + "/" + strconv.Itoa(retries),
			})
			if entry.Retries >= retries {
				entry.State, entry.Retries = "down", 0
				logger.Info(map[string]any{
					"pid":    os.Getpid(),
					"scope":  "check",
					"event":  "down",
					"domain": entry.domain,
					"name":   name,
				})
			}
		}

	} else {
		if pass {
			entry.Retries++
			logger.Info(map[string]any{
				"pid":     os.Getpid(),
				"scope":   "check",
				"event":   "rise",
				"domain":  entry.domain,
				"name":    name,
				"retries": strconv.Itoa(entry.Retries) + "/" + strconv.Itoa(retries),
			})
			if entry.Retries >= retries {
				entry.State, entry.Retries = "up", 0
				logger.Info(map[string]any{
					"pid":    os.Getpid(),
					"scope":  "check",
					"event":  "up",
					"domain": entry.domain,
					"name":   name,
				})
			}

		} else {
			entry.Retries = 0
		}
	}
}

func Check(config *uconfig.UConfig, logger *ulog.ULog) {
	exit := make(chan bool)
	go func() {
		time.Sleep(time.Second)
		select {
		case <-exit:
			return

		default:
		}

		checkMutex.Lock()
		for _, dpath := range config.Paths("domains") {
			for _, cpath := range config.Paths(config.Path(dpath, "checks")) {
				name := config.Base(cpath)
				if _, exists := checkEntries[name]; !exists {
					domain := config.String(config.Path(dpath, "name"))
					checkEntries[name] = &CHECK{Last: 0, State: "up", Latency: 0, Retries: 0, latencies: []int{}, domain: domain}
					logger.Info(map[string]any{
						"pid":    os.Getpid(),
						"scope":  "check",
						"event":  "add",
						"domain": domain,
						"name":   name,
					})
				}
			}
		}
		checkMutex.Unlock()

		for {
			select {
			case <-time.Tick(config.DurationBounds(config.Path("check", "frequency"), 7, 2, 60)):
				checkMutex.Lock()
				for _, dpath := range config.Paths("domains") {
					for _, cpath := range config.Paths(config.Path(dpath, "checks")) {
						name := config.Base(cpath)
						if _, exists := checkEntries[name]; !exists {
							domain := config.String(config.Path(dpath, "name"))
							checkEntries[name] = &CHECK{Last: 0, State: "up", Latency: 0, Retries: 0, latencies: []int{}, domain: domain}
							logger.Info(map[string]any{
								"pid":    os.Getpid(),
								"scope":  "check",
								"event":  "add",
								"domain": domain,
								"name":   name,
							})
						}
						if url := strings.TrimSpace(config.String(config.Path(cpath, "target", "url"))); url != "" {
							headers := map[string]string{}
							for _, path3 := range config.Paths(config.Path(cpath, "target", "headers")) {
								headers[config.Base(path3)] = config.String(path3)
							}
							go checkRun(
								logger,
								config.Base(cpath),
								config.StringMatch(config.Path(cpath, "target", "method"), http.MethodGet, "^(OPTIONS|HEAD|GET|PUT|POST|PATCH|DELETE)$"),
								url,
								config.String(config.Path(cpath, "target", "payload")),
								headers,
								config.String(config.Path(cpath, "status"), `^2\d{2}$`),
								config.String(config.Path(cpath, "headers")),
								config.String(config.Path(cpath, "content")),
								int(config.Integer(config.Path(cpath, "size"))),
								int(config.IntegerBounds(config.Path(cpath, "retries"), 3, 1, 5)),
								config.DurationBounds(config.Path(cpath, "timeout"), 5, 1, 9),
							)
						}
					}
				}
				for name, entry := range checkEntries {
					if entry.Last != 0 && time.Now().Unix()-entry.Last >= 30 {
						delete(checkEntries, name)
						logger.Info(map[string]any{
							"pid":    os.Getpid(),
							"scope":  "check",
							"event":  "remove",
							"domain": entry.domain,
							"name":   name,
						})
					}
				}
				checkMutex.Unlock()

			case <-exit:
				return
			}
		}
	}()

	if parts := strings.Fields(strings.Join(config.Strings(config.Path("check", "listen")), " ")); len(parts) != 0 && parts[0] != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/check", func(response http.ResponseWriter, request *http.Request) {
			checkMutex.RLock()
			content, _ := json.Marshal(checkEntries)
			checkMutex.RUnlock()
			response.Write(content)
		})

		server := &http.Server{
			Handler:      mux,
			ErrorLog:     log.New(io.Discard, "", 0),
			Addr:         strings.TrimLeft(parts[0], "*"),
			ReadTimeout:  7 * time.Second,
			WriteTimeout: 7 * time.Second,
			IdleTimeout:  60 * time.Second,
		}
		if len(parts) == 3 {
			certificates := &dynacert.DYNACERT{}
			certificates.Add("*", parts[1], parts[2])
			server.TLSConfig = certificates.TLSConfig()
			server.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
		}
		if server.TLSConfig != nil {
			server.ListenAndServeTLS("", "")
		} else {
			server.ListenAndServe()
		}
	}

	close(exit)
}
