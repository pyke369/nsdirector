package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pyke369/golang-support/dynacert"
	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/uconfig"
)

type CHECK struct {
	Last      int    `json:"last"`
	State     string `json:"state"`
	Latency   int    `json:"latency"`
	Retries   int    `json:"retries"`
	latencies []int
}

var (
	checks    = map[string]*CHECK{}
	lock      sync.RWMutex
	transport *http.Transport
)

func init() {
	transport = http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableKeepAlives = true
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	transport.DialContext = func(context context.Context, network, address string) (net.Conn, error) {
		if target := context.Value("address"); target != nil && target != "" {
			if _, port, err := net.SplitHostPort(address); err == nil {
				address = fmt.Sprintf("%s:%s", target, port)
			}
		}
		return http.DefaultTransport.(*http.Transport).DialContext(context, network, address)
	}
}

func do(name, method, url, payload string, headers map[string]string, cstatus, cheaders, cpayload string, csize, retries int, timeout time.Duration, metrics bool) {
	var (
		request *http.Request
		address string
		reason  string
		pass    bool
	)

	start := time.Now()
	if matcher := rcache.Get(`^(https?://)([^/]+)(.*)$`); matcher != nil {
		if matches := matcher.FindStringSubmatch(url); matches != nil {
			if parts := strings.Split(matches[2], "|"); len(parts) == 2 {
				address, url = parts[0], matcher.ReplaceAllString(url, "${1}"+parts[1]+"${3}")
			}
		}
	}
	if payload != "" {
		request, _ = http.NewRequest(method, url, bytes.NewBuffer([]byte(payload)))
	} else {
		request, _ = http.NewRequest(method, url, nil)
	}
	request = request.WithContext(context.WithValue(request.Context(), "address", address))
	if request != nil {
		if _, ok := headers["User-Agent"]; !ok {
			request.Header.Add("User-Agent", fmt.Sprintf("%s/%s", progname, version))
		}
		if payload != "" {
			request.Header.Add("Content-Length", fmt.Sprintf("%d", len(payload)))
		}
		for name, value := range headers {
			request.Header.Add(name, value)
		}
		client := &http.Client{Transport: transport, Timeout: timeout}
		if response, err := client.Do(request); err == nil {
			pass = true
			if cstatus != "" {
				if matcher := rcache.Get(cstatus); matcher != nil && !matcher.MatchString(fmt.Sprintf("%d", response.StatusCode)) {
					pass, reason = false, fmt.Sprintf("invalid status code (%d)", response.StatusCode)
				}
			}
			if pass && cheaders != "" {
				if matcher := rcache.Get(cheaders); matcher != nil {
					pass, reason = false, "no matching header"
					for name, _ := range response.Header {
						if matcher.MatchString(fmt.Sprintf("%s: %s", name, response.Header.Get(name))) {
							pass, reason = true, ""
							break
						}
					}
				}
			}
			if pass && (cpayload != "" || csize > 0) {
				if payload, err := ioutil.ReadAll(response.Body); err == nil {
					if cpayload != "" {
						if matcher := rcache.Get(cpayload); matcher != nil && !matcher.Match(payload) {
							pass, reason = false, "no matching payload"
						}
					}
					if csize > 0 {
						if csize > len(payload) {
							pass, reason = false, fmt.Sprintf("payload too small (%d)", len(payload))
						}
					}
				}
			}
			response.Body.Close()
		} else {
			pass, reason = false, fmt.Sprintf("%v", err)
		}
	}

	lock.Lock()
	if _, ok := checks[name]; !ok {
		checks[name] = &CHECK{0, "up", 0, 0, []int{}}
	}
	checks[name].Last = int(time.Now().Unix())
	checks[name].latencies = append(checks[name].latencies, int(time.Now().Sub(start)/time.Millisecond))
	if len(checks[name].latencies) > 5 {
		for index := 0; index < 5; index++ {
			checks[name].latencies[index] = checks[name].latencies[index+1]
		}
		checks[name].latencies = checks[name].latencies[:5]
	}
	latency, divider := 0, 0
	for index := 0; index < len(checks[name].latencies); index++ {
		latency += checks[name].latencies[index] * (index + 1)
		divider += (index + 1)
	}
	checks[name].Latency = latency / divider
	if checks[name].State == "up" {
		if pass {
			checks[name].Retries = 0
		} else {
			checks[name].Retries++
			logger.Info(map[string]interface{}{"event": "fall", "pid": os.Getpid(), "check": name,
				"reason": reason, "retries": fmt.Sprintf("%d/%d", checks[name].Retries, retries)})
			if checks[name].Retries >= retries {
				checks[name].State = "down"
				checks[name].Retries = 0
				logger.Info(map[string]interface{}{"event": "down", "pid": os.Getpid(), "check": name})
			}
		}
	} else {
		if pass {
			checks[name].Retries++
			logger.Info(map[string]interface{}{"event": "rise", "pid": os.Getpid(), "check": name,
				"retries": fmt.Sprintf("%d/%d", checks[name].Retries, retries)})
			if checks[name].Retries >= retries {
				checks[name].State = "up"
				checks[name].Retries = 0
				logger.Info(map[string]interface{}{"event": "up", "pid": os.Getpid(), "check": name})
			}
		} else {
			checks[name].Retries = 0
		}
	}
	if metrics {
		metricsGauge("state", int64(-strings.Index(checks[name].State, "down")), map[string]interface{}{"check": name})
		metricsGauge("latency", int64(checks[name].Latency), map[string]interface{}{"check": name})
	}
	lock.Unlock()
}

func check(listen string) {
	exit := make(chan bool)

	go func() {
		lock.Lock()
		for _, path1 := range config.GetPaths("domains") {
			for _, path2 := range config.GetPaths(path1 + ".checks") {
				name := strings.TrimPrefix(path2, path1+".checks.")
				if _, ok := checks[name]; !ok {
					checks[name] = &CHECK{0, "up", 0, 0, []int{}}
					logger.Info(map[string]interface{}{"event": "add", "pid": os.Getpid(), "check": name})
				}
			}
		}
		for name, check := range checks {
			if check.Last != 0 && int(time.Now().Unix())-check.Last >= 30 {
				delete(checks, name)
				logger.Info(map[string]interface{}{"event": "remove", "pid": os.Getpid(), "check": name})
			}
		}
		lock.Unlock()

		ticker := time.NewTicker(uconfig.Duration(config.GetDurationBounds("director.checks.frequency", 10, 2, 60)))
		for {
			select {
			case <-ticker.C:
				for _, path1 := range config.GetPaths("domains") {
					for _, path2 := range config.GetPaths(path1 + ".checks") {
						if url := strings.TrimSpace(config.GetString(path2+".target.url", "")); url != "" {
							headers := map[string]string{}
							for _, path3 := range config.GetPaths(path2 + ".target.headers") {
								headers[strings.TrimPrefix(path3, path2+".target.headers.")] = config.GetString(path3, "")
							}
							go do(strings.TrimPrefix(path2, path1+".checks."),
								config.GetStringMatch(path2+".target.method", http.MethodGet, "^(OPTIONS|HEAD|GET|PUT|POST|PATCH|DELETE)$"),
								url,
								config.GetString(path2+".target.payload", ""),
								headers,
								config.GetString(path2+".status", `^2\d{2}$`),
								config.GetString(path2+".headers", ""),
								config.GetString(path2+".content", ""),
								int(config.GetInteger(path2+".size", 0)),
								int(config.GetIntegerBounds(path2+".retries", 3, 1, 5)),
								uconfig.Duration(config.GetDurationBounds(path2+".timeout", 3, 1, 9)),
								config.GetBoolean(path2+".metrics", true),
							)
						}
					}
				}
			case <-exit:
				return
			}
		}
		ticker.Stop()
	}()

	handler := http.NewServeMux()
	handler.HandleFunc("/checks", func(response http.ResponseWriter, request *http.Request) {
		lock.RLock()
		content, _ := json.Marshal(checks)
		lock.RUnlock()
		response.Write(content)
	})

	if parts := strings.Split(listen, ","); parts[0] != "" {
		server := &http.Server{
			Addr:         strings.TrimLeft(parts[0], "*"),
			ReadTimeout:  uconfig.Duration(config.GetDurationBounds("director.read_timeout", 10, 5, 30)),
			WriteTimeout: uconfig.Duration(config.GetDurationBounds("director.write_timeout", 10, 5, 30)),
			IdleTimeout:  uconfig.Duration(config.GetDurationBounds("director.idle_timeout", 30, 5, 30)),
			Handler:      handler,
		}
		if len(parts) > 1 {
			loader := &dynacert.DYNACERT{Public: parts[1], Key: parts[2]}
			server.TLSConfig = dynacert.IntermediateTLSConfig(loader.GetCertificate)
			server.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
			server.ListenAndServeTLS(parts[1], parts[2])
		} else {
			server.ListenAndServe()
		}
	}

	close(exit)
	time.Sleep(time.Second)
}
