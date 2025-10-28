package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"hash/crc32"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pyke369/golang-support/dynacert"
	"github.com/pyke369/golang-support/file"
	"github.com/pyke369/golang-support/fqdn"
	j "github.com/pyke369/golang-support/jsonrpc"
	"github.com/pyke369/golang-support/prefixdb"
	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/uconfig"
	"github.com/pyke369/golang-support/ulog"
	"github.com/pyke369/golang-support/uuid"
)

type CONDITION struct {
	include  []string
	exclude  []string
	provider string
	selector string
}

type RECORD struct {
	name    string
	ttl     int
	weight  int
	options []string
}

type REMATCH struct {
	empty   []string
	exclude []string
}

type RULE struct {
	name       string
	path       string
	priority   int
	affinity   bool
	final      bool
	group      string
	conditions map[string]*CONDITION
	records    map[string][]*RECORD
	rematch    *REMATCH
}

var (
	backendWatch    = map[string]string{}
	backendGeobases = []*prefixdb.PrefixDB{}
	backendDomains  = map[string]string{}
	backendEntries  = map[string][]*RULE{}
	backendChecks   = map[string]map[string]CHECK{}
	backendCTypes   = []string{"continent", "country", "region", "state", "asnum", "cidr", "square", "distance", "identity", "time", "availability", "latency"}
	backendRTypes   = []string{"cname", "a", "aaaa", "loc", "mx", "ptr", "srv", "txt"}
	backendDays     = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}
)

func backendParse(rtype, in string, ttl int) (record *RECORD) {
	if fields := strings.Split(in, "|"); len(fields) > 0 {
		if value := strings.TrimSpace(fields[0]); value != "" {
			record = &RECORD{name: value, ttl: ttl, weight: 1}
			if len(fields) > 1 {
				if ttl, err := strconv.Atoi(fields[1]); err == nil && ttl != 0 {
					record.ttl = int(math.Min(86400, math.Max(10, float64(ttl))))
				}
			}
			if len(fields) > 2 {
				if weight, err := strconv.Atoi(fields[2]); err == nil {
					record.weight = int(math.Min(100, math.Max(-1, float64(weight))))
				}
			}
			if len(fields) > 3 && (rtype == "mx" || rtype == "srv") {
				record.options = fields[3:]
			}

			switch rtype {
			case "mx":
				if len(record.options) < 1 {
					return nil
				}
				if value, err := strconv.Atoi(record.options[0]); err != nil || value < 1 || value > 100 {
					return nil
				}
				record.options = record.options[:1]

			case "srv":
				if len(record.options) < 3 {
					return nil
				}
				if value, err := strconv.Atoi(record.options[0]); err != nil || value < 0 || value > 100 {
					return nil
				}
				if value, err := strconv.Atoi(record.options[1]); err != nil || value < 0 || value > 65535 {
					return nil
				}
				if value, err := strconv.Atoi(record.options[2]); err != nil || value < 1 || value > 65535 {
					return nil
				}
				record.options = record.options[:3]

			case "loc": // TODO not implemented yet
			}
		}
	}

	return
}

func backendLoadGeobases(config *uconfig.UConfig, logger *ulog.ULog) {
	bases := []*prefixdb.PrefixDB{}
	for _, path := range config.Strings("geobase") {
		base := prefixdb.New()
		if err := base.Load(path); err == nil {
			bases = append(bases, base)
			logger.Info(map[string]any{
				"pid":         os.Getpid(),
				"scope":       "backend",
				"event":       "geobase",
				"path":        path,
				"description": base.Description,
			})
		}
	}
	backendGeobases = bases
	runtime.GC()
}

func backendLoadEntries(config *uconfig.UConfig) {
	ndomains, nentries := map[string]string{}, map[string][]*RULE{}
	for _, path := range config.Paths("domains") {
		if domain := strings.TrimSpace(config.String(config.Path(path, "name"))); domain != "" {
			ndomains[domain] = path
			ttl := int(config.IntegerBounds(config.Path(path, "ttl"), 600, 10, 86400))
			for _, path := range config.Paths(config.Path(path, "entries")) {
				if entry := strings.TrimSpace(config.String(config.Path(path, "name"))); entry != "" {
					rules := []*RULE{}
					for _, rpath := range config.Paths(config.Path(path, "rules")) {
						rule := &RULE{
							name:       strings.ToLower(config.Base(rpath)),
							path:       path,
							priority:   int(config.IntegerBounds(config.Path(rpath, "priority"), 1, 1, 100)),
							affinity:   config.Boolean(config.Path(rpath, "affinity"), true),
							final:      config.Boolean(config.Path(rpath, "final"), true),
							group:      config.String(config.Path(rpath, "group")),
							conditions: map[string]*CONDITION{},
							records:    map[string][]*RECORD{},
						}

						for _, ctype := range backendCTypes {
							for _, value := range config.Strings(config.Path(rpath, ctype, "include")) {
								if rule.conditions[ctype] == nil {
									rule.conditions[ctype] = &CONDITION{}
								}
								rule.conditions[ctype].include = append(rule.conditions[ctype].include, strings.ToLower(value))
							}
							for _, value := range config.Strings(config.Path(rpath, ctype, "exclude")) {
								if rule.conditions[ctype] == nil {
									rule.conditions[ctype] = &CONDITION{}
								}
								rule.conditions[ctype].exclude = append(rule.conditions[ctype].exclude, strings.ToLower(value))
							}
							for _, value := range config.Strings(config.Path(rpath, ctype, "provider")) {
								if rule.conditions[ctype] == nil {
									rule.conditions[ctype] = &CONDITION{}
								}
								rule.conditions[ctype].provider = value
								break
							}
							for _, value := range config.Strings(config.Path(rpath, ctype, "selector")) {
								if rule.conditions[ctype] == nil {
									rule.conditions[ctype] = &CONDITION{}
								}
								rule.conditions[ctype].selector = strings.ToLower(value)
								break
							}
						}

						for _, rtype := range backendRTypes {
							for _, value := range config.Strings(config.Path(rpath, "records", rtype)) {
								if record := backendParse(rtype, value, ttl); record != nil {
									rule.records[rtype] = append(rule.records[rtype], record)
								}
							}
						}
						empty, exclude := []string{}, config.Strings(config.Path(rpath, "rematch", "exclude"))
						for _, rtype := range config.Strings(config.Path(rpath, "rematch", "empty")) {
							if rtype := strings.ToLower(rtype); slices.Contains(backendRTypes, rtype) {
								empty = append(empty, rtype)
							}
						}
						if len(empty) != 0 && len(exclude) != 0 {
							for index := 0; index < len(exclude); index++ {
								exclude[index] = strings.ToLower(exclude[index])
							}
							rule.rematch = &REMATCH{empty, exclude}
						}

						if len(rule.records) != 0 || rule.rematch != nil {
							rules = append(rules, rule)
						}
					}
					sort.Slice(rules, func(i, j int) bool {
						if rules[i].priority > rules[j].priority {
							return true
						}
						if rules[i].priority == rules[j].priority {
							if rules[i].group < rules[j].group {
								return true
							}
							if rules[i].group == rules[j].group {
								return rules[i].name < rules[j].name
							}
						}
						return false
					})
					nentries[entry+"."+domain] = rules
				}
			}
		}
	}
	backendDomains, backendEntries = ndomains, nentries
}

func backendReload(config *uconfig.UConfig, logger *ulog.ULog) {
	changes := false
	for _, path := range config.Strings("watch") {
		if info, err := os.Stat(path); err == nil {
			if time.Since(info.ModTime()) >= 5*time.Second {
				sum, _ := file.Sum(path)
				if osum, exists := backendWatch[path]; !exists || (exists && osum != sum) {
					changes = true
				}
				backendWatch[path] = sum
			}

		} else {
			backendWatch[path] = ""
		}
	}
	if changes {
		config.Reload()
		logger.Load(config.String("log", "console()"))
		logger.Info(map[string]any{
			"pid":     os.Getpid(),
			"scope":   "backend",
			"event":   "reload",
			"version": PROGVER,
		})
		backendLoadGeobases(config, logger)
		backendLoadEntries(config)
		go Check(config, logger)
	}

	client, checks := &http.Client{Timeout: 5 * time.Second}, map[string]map[string]CHECK{}
	for _, path := range config.Paths(config.Path("check", "source")) {
		if response, err := client.Get(config.String(path, "")); err == nil {
			if body, err := io.ReadAll(response.Body); err == nil {
				result := map[string]CHECK{}
				if json.Unmarshal(body, &result) == nil {
					checks[config.Base(path)] = result
				}
			}
			response.Body.Close()
		}
	}
	backendChecks = checks
}

func backendNets(in []string, address string) bool {
	if ip := net.ParseIP(address); ip != nil {
		for _, value := range in {
			if _, network, err := net.ParseCIDR(value); err == nil {
				if network.Contains(ip) {
					return true
				}
			}
		}
	}

	return false
}

func backendSquares(in []string, lat, lon float64) bool {
	matcher := rcache.Get(`^([\-+]*\d+(?:\.\d+)?)[:\|]([\-+]*\d+(?:\.\d+)?)\s+([\-+]*\d+(?:\.\d+)?)[:\|]([\-+]*\d+(?:\.\d+)?)$`)
	for _, value := range in {
		captures := matcher.FindStringSubmatch(value)
		if captures == nil {
			continue
		}
		lat1, lon1, lat2, lon2 := j.Number(captures[1]), j.Number(captures[2]), j.Number(captures[3]), j.Number(captures[4])
		if lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180 &&
			lat1 >= -90 && lat1 <= 90 && lon1 >= -180 && lon1 <= 180 &&
			lat2 >= -90 && lat2 <= 90 && lon2 >= -180 && lon2 <= 180 &&
			lat1 > lat2 && lon1 < lon2 &&
			lat1 >= lat && lat >= lat2 && lon1 <= lon && lon <= lon2 {
			return true
		}
	}

	return false
}

func backendDistance(lat1, lon1, lat2, lon2 float64) float64 {
	if (lat1 == 0 && lon1 == 0) || (lat2 == 0 && lon2 == 0) {
		return -1
	}
	lat1 *= math.Pi / 180
	lon1 *= math.Pi / 180
	lat2 *= math.Pi / 180
	lon2 *= math.Pi / 180
	dlat, dlon := (lat2-lat1)/2, (lon2-lon1)/2
	a := (math.Sin(dlat) * math.Sin(dlat)) + math.Cos(lat1)*math.Cos(lat2)*(math.Sin(dlon)*math.Sin(dlon))
	d := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return (6378137 * d) / 1000
}

func backendNearest(config *uconfig.UConfig, lat1, lon1 float64, selector string, extra ...[]string) string {
	highest, name, matcher, exclude := 100000.0, "", rcache.Get(`^([\-+]*\d+(?:\.\d+)?)[:\|]([\-+]*(?:\d+\.\d+)?)(?:[:\|]([\-+]*\d{1,2}))?$`), []string{}
	if len(extra) != 0 {
		exclude = extra[0]
	}

	for _, path := range config.Paths(selector) {
		if slices.Contains(exclude, config.Base(path)) {
			continue
		}

		captures := matcher.FindStringSubmatch(config.String(path))
		if captures == nil {
			continue
		}

		lat2, lon2 := j.Number(captures[1]), j.Number(captures[2])
		value := backendDistance(lat1, lon1, lat2, lon2)
		if bias := j.Number(captures[3]); bias != 0 {
			if bias > 0 {
				value *= (1 - (bias / 100))

			} else {
				value /= (1 + (bias / 100))
			}
		}
		if value < highest {
			highest, name = value, config.Base(path)
		}
	}

	return name
}

func backendTimes(in []string) bool {
	now := time.Now()
	dmatcher := rcache.Get(`^\d{4}-\d{2}-\d{2}(?:[Tt]\d{2}:\d{2}(?::\d{2})?)?(?:[zZ]|[+\-]\d{2}:?\d{2})?$`)
	tmatcher := rcache.Get(`^([01]\d|2[0-3]):([0-5]\d)$`)
	for _, value := range in {
		for _, predicate := range strings.Split(value, "|") {
			parts := strings.Fields(predicate)
			if len(parts) == 0 {
				continue
			}
			if dmatcher.MatchString(parts[0]) {
				if start, err := time.Parse(time.RFC3339, strings.ToUpper(parts[0])); err != nil {
					return false

				} else if now.Sub(start) < 0 {
					return false

				} else if len(parts) >= 2 {
					if end, err := time.Parse(time.RFC3339, strings.ToUpper(parts[1])); err != nil {
						return false

					} else if now.Sub(end) >= 0 {
						return false
					}
				}

			} else if rcache.Get(`^(mon|tue|wed|thu|fri|sat|sun)$`).MatchString(parts[0]) {
				day, matched := backendDays[now.Weekday()], false
				for _, pday := range parts {
					if day == pday {
						matched = true
						break
					}
				}
				if !matched {
					return false
				}

			} else if captures := tmatcher.FindStringSubmatch(parts[0]); captures != nil {
				hours, _ := strconv.Atoi(captures[1])
				minutes, _ := strconv.Atoi(captures[2])
				if (now.UTC().Hour()*60)+now.UTC().Minute() < (hours*60)+minutes {
					return false
				}

				if len(parts) >= 2 {
					if captures := tmatcher.FindStringSubmatch(parts[1]); captures == nil {
						return false

					} else {
						hours, _ := strconv.Atoi(captures[1])
						minutes, _ := strconv.Atoi(captures[2])
						if (now.UTC().Hour()*60)+now.UTC().Minute() >= (hours*60)+minutes {
							return false
						}
					}
				}
			}
		}
	}

	return true
}

func backendPassed(in []string) bool {
	if len(backendChecks) == 0 {
		return true
	}

	for _, check := range in {
		source := ""
		if parts := strings.Split(check, "@"); len(parts) > 1 {
			check, source = parts[0], parts[1]
		}
		if source != "" {
			if value, exists := backendChecks[source]; !exists {
				continue

			} else {
				if value, exists := value[check]; !exists {
					return true

				} else if value.State == "up" {
					return true
				}
			}

		} else {
			found := false
			for _, value := range backendChecks {
				if value, exists := value[check]; exists {
					found = true
					if value.State == "up" {
						return true
					}
				}
			}
			if !found {
				return true
			}
		}
	}

	return false
}

func backendResponse(qname, rtype string, record *RECORD, rfields map[string]string) string {
	line, name := "", record.name
	for key, value := range rfields {
		if key == "cncode" || key == "ccode" || key == "asnum" {
			value = strings.ToUpper(value)
		}
		name = strings.ReplaceAll(name, "{{"+key+"}}", value)
	}
	name = rcache.Get(`\{\{[^\}]*\}\}`).ReplaceAllString(name, "")

	switch rtype {
	case "a", "aaaa", "cname", "ptr":
		line = rfields["bits"] + "\t1\t" + qname + "\tIN\t" + strings.ToUpper(rtype) + "\t" + strconv.Itoa(record.ttl) + "\t-1\t" + name

	case "mx":
		line = rfields["bits"] + "\t1\t" + qname + "\tIN\tMX\t" + strconv.Itoa(record.ttl) + "\t-1\t" + record.options[0] + "\t" + name

	case "srv":
		line = rfields["bits"] + "\t1\t" + qname + "\tIN\tSRV\t" + strconv.Itoa(record.ttl) + "\t-1\t" + record.options[0] + "\t" + record.options[1] + " " + record.options[2] + " " + name

	case "txt":
		line = rfields["bits"] + "\t1\t" + qname + "\tIN\tTXT\t" + strconv.Itoa(record.ttl) + "\t-1\t" + `"` + strings.ReplaceAll(name, `"`, `\"`) + `"`

	case "loc": // TODO not implemented yet
	}

	return line
}

func backendLookup(config *uconfig.UConfig, qname, qtype, remote string) (result []string) {
	result = []string{}
	length := len(backendEntries[qname])
	if backendDomains[qname] != "" || length > 0 {
		domain := qname
		if length > 0 {
			domain = strings.SplitN(qname, ".", 2)[1]
		}
		if qtype == "SOA" || qtype == "ANY" {
			server, contact := config.Strings(config.Path(backendDomains[domain], "servers"), []string{"ns." + domain})[0], config.String(config.Path(backendDomains[domain], "contact"), "contact@"+domain)
			if index := strings.Index(contact, "@"); index > 0 && index < len(contact)-1 {
				contact = strings.ReplaceAll(contact[:index], ".", `\.`) + "." + contact[index+1:]
			}
			contact = strings.ReplaceAll(contact, "@", ".")
			result = append(result, "0\t1\t"+qname+"\tIN\tSOA\t7200\t-1\t"+server+"\t"+contact+"\t"+time.Now().UTC().Format("2006010215")+"\t86400\t7200\t604800\t172800")
		}
		if qtype == "NS" || qtype == "ANY" {
			for _, path := range config.Paths(config.Path(backendDomains[domain], "servers")) {
				if server := strings.TrimSpace(config.String(path)); server != "" {
					result = append(result, "0\t1\t"+qname+"\tIN\tNS\t7200\t-1\t"+server)
				}
			}
		}

		if length > 0 && qtype != "SOA" && qtype != "NS" {
			rfields := map[string]string{"remote": "0.0.0.0", "bits": "32", "identity": config.String("identity")}
			rfields["hostname"], _ = fqdn.FQDN()
			if address, network, err := net.ParseCIDR(remote); err == nil {
				bits, _ := network.Mask.Size()
				rfields["bits"] = strconv.Itoa(bits)
				rfields["remote"] = address.String()

				geoinfo := map[string]any{}
				for _, base := range backendGeobases {
					base.Lookup(address.String(), geoinfo)
				}
				if value := strings.ToLower(j.String(geoinfo["continent_code"])); value != "" {
					rfields["continent"], rfields["cncode"] = value, value
				}
				if value := j.String(geoinfo["continent_name"]); value != "" {
					rfields["cnname"] = value
				}
				if value := strings.ToLower(j.String(geoinfo["country_code"])); value != "" {
					rfields["country"], rfields["ccode"] = value, value
				}
				if value := j.String(geoinfo["country_name"]); value != "" {
					rfields["cname"] = value
				}
				if value := j.String(geoinfo["region_code"]); value != "" {
					rfields["region"], rfields["rcode"] = strings.ToLower(value), value
				}
				if value := j.String(geoinfo["region_name"]); value != "" {
					rfields["rname"] = value
				}
				if value := j.String(geoinfo["state_code"]); value != "" {
					rfields["state"], rfields["scode"] = strings.ToLower(value), value
				}
				if value := j.String(geoinfo["state_name"]); value != "" {
					rfields["sname"] = value
				}
				if value := j.String(geoinfo["city_name"]); value != "" {
					rfields["city"] = value
				}
				if value := strings.ToLower(j.String(geoinfo["as_number"])); value != "" {
					rfields["asnum"] = value
				}
				if value := j.String(geoinfo["as_name"]); value != "" {
					rfields["asname"] = value
				}
				if value := j.Number(geoinfo["latitude"], -1000); value != -1000 {
					rfields["latitude"] = strconv.FormatFloat(value, 'f', -1, 64)
					rfields["lat"] = rfields["latitude"]
				}
				if value := j.Number(geoinfo["longitude"], -1000); value != -1000 {
					rfields["longitude"] = strconv.FormatFloat(value, 'f', -1, 64)
					rfields["lon"] = rfields["longitude"]
				}
			}

			records, exclude, matcher, affinity := map[string][]*RECORD{}, []string{}, rcache.Get(`^([\-+]*\d+(?:\.\d+)?)[:\|]([\-+]*(?:\d+\.\d+)?)(?:[:\|]([\-+]*\d{1,2}))?$`), true
		done:
			for rematch := 1; rematch <= int(config.IntegerBounds("rematch", 5, 1, 10)); rematch++ {
				records = map[string][]*RECORD{}
				completed := true
				for _, rule := range backendEntries[qname] {
					match := true
					for _, ctype := range backendCTypes {
						if condition := rule.conditions[ctype]; condition != nil {
							switch ctype {
							case "continent", "country", "region", "state", "asnum", "identity":
								if rfields[ctype] == "" {
									match = false

								} else if (len(condition.include) > 0 && !slices.Contains(condition.include, rfields[ctype])) ||
									(len(condition.exclude) > 0 && slices.Contains(condition.exclude, rfields[ctype])) {
									match = false
								}

							case "cidr":
								if (len(condition.include) > 0 && !backendNets(condition.include, rfields["remote"])) ||
									(len(condition.exclude) > 0 && backendNets(condition.exclude, rfields["remote"])) {
									match = false
								}

							case "square", "distance":
								if captures := matcher.FindStringSubmatch(rfields["latitude"] + ":" + rfields["longitude"]); captures == nil {
									match = false

								} else {
									lat, lon := j.Number(captures[1]), j.Number(captures[2])
									switch ctype {
									case "square":
										if (len(condition.include) > 0 && !backendSquares(condition.include, lat, lon)) ||
											(len(condition.exclude) > 0 && backendSquares(condition.exclude, lat, lon)) {
											match = false
										}

									case "distance":
										selector := condition.selector
										if selector[0] == '/' {
											selector = selector[1:]

										} else {
											selector = config.Path(rule.path, selector)
										}
										if name := backendNearest(config, lat, lon, selector, exclude); name == "" {
											match = false

										} else if (len(condition.include) > 0 && !slices.Contains(condition.include, name)) ||
											(len(condition.exclude) > 0 && slices.Contains(condition.exclude, name)) {
											match = false
										}
									}
								}

							case "time":
								if (len(condition.include) > 0 && !backendTimes(condition.include)) ||
									(len(condition.exclude) > 0 && backendTimes(condition.exclude)) {
									match = false
								}

							case "availability":
								if (len(condition.include) > 0 && !backendPassed(condition.include)) ||
									(len(condition.exclude) > 0 && backendPassed(condition.exclude)) {
									match = false
								}

							case "latency": // TODO not implemented yet
							}
						}
						if !match {
							break
						}
					}
					if match {
						for rtype, record := range rule.records {
							records[rtype] = append(records[rtype], record...)
						}
						if rule.rematch != nil {
							empty := false
							for _, rtype := range rule.rematch.empty {
								if len(records[rtype]) == 0 {
									empty = true
									break
								}
							}
							if empty {
								exclude = append(exclude, rule.rematch.exclude...)
								completed = false
								break
							}
						}
						affinity = rule.affinity
						if rule.final {
							break done
						}
					}
				}
				if completed {
					break done
				}
			}

			for _, rtype := range backendRTypes {
				if strings.EqualFold(qtype, rtype) || qtype == "ANY" {
					weights, responded := []int{}, false
					for position, record := range records[rtype] {
						if record.weight >= 0 {
							for index := 0; index < record.weight; index++ {
								weights = append(weights, position)
							}

						} else {
							result = append(result, backendResponse(qname, rtype, record, rfields))
							responded = true
							if rtype == "cname" {
								break
							}
						}
					}
					if !responded && len(weights) > 0 {
						position := 0
						if affinity {
							position = int(crc32.ChecksumIEEE([]byte(remote))) % len(weights)

						} else {
							position = rand.Int() % len(weights)
						}
						result = append(result, backendResponse(qname, rtype, records[rtype][weights[position]], rfields))
						responded = true
					}
					if responded && rtype == "cname" {
						break
					}
				}
			}
		}
	}

	return
}

func Backend(configuration string) (err error) {
	config, err := uconfig.New(configuration)
	if err != nil {
		return err
	}
	config.SetPrefix(PROGNAME)

	logger := ulog.New(config.String("log", "console()"))
	logger.SetOrder([]string{
		"pid", "scope", "event", "version", "config", "path", "description", "mode", "listen",
		"certificate", "domain", "name", "reason", "retries", "id", "request", "response",
	})
	logger.Info(map[string]any{
		"pid":     os.Getpid(),
		"scope":   "backend",
		"event":   "start",
		"version": PROGVER,
		"config":  configuration,
	})

	go func() {
		for {
			backendReload(config, logger)
			time.Sleep(5 * time.Second)
		}
	}()

	if parts := strings.Fields(strings.Join(config.Strings("listen"), " ")); len(parts) != 0 && parts[0] != "" {
		// remote backend
		go func() {
			mux := http.NewServeMux()
			mux.HandleFunc("/", func(response http.ResponseWriter, request *http.Request) {
				response.Header().Set("Content-Type", "application/json")

				result := map[string]any{"result": false}
				body, _ := io.ReadAll(request.Body)
				payload := map[string]any{}
				json.Unmarshal(body, &payload)
				if j.String(payload["method"]) == "lookup" {
					qname, qtype, remote := "", "", ""
					for name, value := range j.StringMap(payload["parameters"]) {
						switch name {
						case "qname":
							qname = strings.ToLower(strings.TrimRight(value, "."))

						case "qtype":
							qtype = value

						case "real-remote":
							remote = value
						}
					}

					if qname != "" && qtype != "" {
						id, list := uuid.New(), [][]any{}
						logger.Debug(map[string]any{
							"pid":     os.Getpid(),
							"scope":   "backend",
							"event":   "request",
							"mode":    "remote",
							"id":      id.String(),
							"request": []any{qname, qtype, remote},
						})

						records := []map[string]any{}
						for _, line := range backendLookup(config, qname, qtype, remote) {
							if fields := strings.Split(line, "\t"); len(fields) >= 7 {
								scope, _ := strconv.Atoi(fields[0])
								ttl, _ := strconv.Atoi(fields[5])
								records = append(records, map[string]any{
									"scopeMask": scope,
									"qname":     fields[2],
									"qtype":     fields[4],
									"ttl":       ttl,
									"content":   strings.Join(fields[7:], "\t"),
								})
								list = append(list, []any{fields[2], fields[4], ttl, strings.Join(fields[7:], " ")})
							}
						}
						result["result"] = records

						logger.Debug(map[string]any{
							"pid":      os.Getpid(),
							"scope":    "backend",
							"event":    "response",
							"mode":     "remote",
							"id":       id.String(),
							"response": list,
						})
					}
				}

				if payload, err := json.Marshal(result); err == nil {
					response.Write(payload)
				}
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
				logger.Info(map[string]any{
					"pid":         os.Getpid(),
					"scope":       "backend",
					"event":       "listen",
					"mode":        "https",
					"listen":      parts[0],
					"certificate": parts[1:],
				})
				server.ListenAndServeTLS("", "")

			} else {
				logger.Info(map[string]any{
					"pid":    os.Getpid(),
					"scope":  "backend",
					"event":  "listen",
					"mode":   "http",
					"listen": parts[0],
				})
				server.ListenAndServe()
			}
		}()
	}

	// pipe backend
	reader := bufio.NewReader(os.Stdin)
	for {
		if line, err := reader.ReadString('\n'); err != nil {
			break

		} else {
			fields := strings.Split(strings.TrimSpace(line), "\t")
			switch {
			case len(fields) == 2 && fields[0] == "HELO":
				if fields[1] != "3" {
					os.Stdout.WriteString("FAIL invalid ABI version " + fields[1] + "\n")

				} else {
					os.Stdout.WriteString("OK " + strconv.Itoa(os.Getpid()) + " " + PROGNAME + "/" + PROGVER + " ready\n")
				}

			case len(fields) == 8 && fields[0] == "Q" && fields[2] == "IN":
				if fields[1] != "" && fields[3] != "" {
					id, list := uuid.New(), [][]any{}
					logger.Debug(map[string]any{
						"pid":     os.Getpid(),
						"scope":   "backend",
						"event":   "request",
						"mode":    "pipe",
						"id":      id.String(),
						"request": []any{fields[1], fields[3], fields[7]},
					})

					for _, line := range backendLookup(config, strings.ToLower(fields[1]), fields[3], fields[7]) {
						if fields := strings.Split(line, "\t"); len(fields) >= 7 {
							os.Stdout.WriteString("DATA\t" + line + "\n")
							ttl, _ := strconv.Atoi(fields[5])
							list = append(list, []any{fields[2], fields[4], ttl, strings.Join(fields[7:], " ")})
						}
					}

					logger.Debug(map[string]any{
						"pid":      os.Getpid(),
						"scope":    "backend",
						"event":    "response",
						"mode":     "pipe",
						"id":       id.String(),
						"response": list,
					})
				}
				os.Stdout.WriteString("END\n")

			default:
				os.Stdout.WriteString("FAIL invalid backend request\n")
			}
		}
	}

	logger.Info(map[string]any{
		"pid":     os.Getpid(),
		"scope":   "backend",
		"event":   "stop",
		"version": PROGVER,
		"config":  configuration,
	})

	return
}
