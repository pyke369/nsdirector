package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pyke369/golang-support/fqdn"
	"github.com/pyke369/golang-support/prefixdb"
	"github.com/pyke369/golang-support/uconfig"
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
type RULE struct {
	name       string
	path       string
	priority   int
	affinity   bool
	final      bool
	conditions map[string]*CONDITION
	records    map[string][]*RECORD
}
type BYPRIORITY []RULE

func (a BYPRIORITY) Len() int      { return len(a) }
func (a BYPRIORITY) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a BYPRIORITY) Less(i, j int) bool {
	return a[i].priority > a[j].priority ||
		(a[i].priority == a[j].priority && strings.Compare(a[i].name, a[j].name) < 0)
}

var (
	config    *uconfig.UConfig
	trace     bool
	geobases  = []*prefixdb.PrefixDB{}
	rchecks   = map[string]map[string]CHECK{}
	clock     sync.RWMutex
	watched   = map[string]string{}
	domains   = map[string]string{}
	entries   = map[string][]RULE{}
	ctypes    = []string{"continent", "country", "region", "state", "asnum", "cidr", "square", "distance", "identity", "time", "availability", "latency"}
	rtypes    = []string{"cname", "a", "aaaa", "loc", "mx", "ptr", "srv", "txt"}
	pmatcher  = regexp.MustCompile(`^([\-+]*\d+(?:\.\d+)?)[:\|]([\-+]*(?:\d+\.\d+)?)(?:[:\|]([\-+]*\d{1,2}))?$`)
	sqmatcher = regexp.MustCompile(`^([\-+]*\d+(?:\.\d+)?)[:\|]([\-+]*\d+(?:\.\d+)?)\s+([\-+]*\d+(?:\.\d+)?)[:\|]([\-+]*\d+(?:\.\d+)?)$`)
	dmatcher  = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}(?:[Tt]\d{2}:\d{2}(?::\d{2})?)?(?:[zZ]|[+\-]\d{2}:?\d{2})?$`)
	tmatcher  = regexp.MustCompile(`^([01][0-9]|2[0-3]):([0-5][0-9])$`)
	wmatcher  = regexp.MustCompile(`^(mon|tue|wed|thu|fri|sat|sun)$`)
	weekdays  = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}
	mreplacer = regexp.MustCompile(`\{\{[^\}]*\}\}`)
)

func parseRecord(rtype, input string, ttl int) (record *RECORD) {
	if fields := strings.Split(input, "|"); len(fields) > 0 {
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
			case "loc": // TODO not implemented yet
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

			}
		}
	}
	return
}

func loadCaches() {
	if config != nil {
		ndomains, nentries := map[string]string{}, map[string][]RULE{}
		for _, path := range config.GetPaths("domains") {
			if domain := strings.TrimSpace(config.GetString(path+".name", "")); domain != "" {
				ndomains[domain] = path
				ttl := int(config.GetIntegerBounds(path+".ttl", 600, 10, 86400))
				for _, path := range config.GetPaths(path + ".entries") {
					if entry := strings.TrimSpace(config.GetString(path+".name", "")); entry != "" {

						rules := []RULE{}
						for _, rpath := range config.GetPaths(path + ".rules") {
							rule := RULE{
								name:       strings.ToLower(strings.TrimPrefix(rpath, path+".rules.")),
								path:       path,
								priority:   int(config.GetIntegerBounds(rpath+".priority", 1, 1, 100)),
								affinity:   config.GetBoolean(rpath+".affinity", true),
								final:      config.GetBoolean(rpath+".final", true),
								conditions: map[string]*CONDITION{},
								records:    map[string][]*RECORD{},
							}

							for _, ctype := range ctypes {
								if cvalue := strings.TrimSpace(config.GetString(rpath+"."+ctype+".include", "")); cvalue != "" {
									if rule.conditions[ctype] == nil {
										rule.conditions[ctype] = &CONDITION{}
									}
									rule.conditions[ctype].include = append(rule.conditions[ctype].include, strings.ToLower(cvalue))
								}
								for _, cpath := range config.GetPaths(rpath + "." + ctype + ".include") {
									if cvalue := strings.TrimSpace(config.GetString(cpath, "")); cpath != "" {
										if rule.conditions[ctype] == nil {
											rule.conditions[ctype] = &CONDITION{}
										}
										rule.conditions[ctype].include = append(rule.conditions[ctype].include, strings.ToLower(cvalue))
									}
								}
								if cvalue := strings.TrimSpace(config.GetString(rpath+"."+ctype+".exclude", "")); cvalue != "" {
									if rule.conditions[ctype] == nil {
										rule.conditions[ctype] = &CONDITION{}
									}
									rule.conditions[ctype].exclude = append(rule.conditions[ctype].exclude, strings.ToLower(cvalue))
								}
								for _, cpath := range config.GetPaths(rpath + "." + ctype + ".exclude") {
									if cvalue := strings.TrimSpace(config.GetString(cpath, "")); cvalue != "" {
										if rule.conditions[ctype] == nil {
											rule.conditions[ctype] = &CONDITION{}
										}
										rule.conditions[ctype].exclude = append(rule.conditions[ctype].exclude, strings.ToLower(cvalue))
									}
								}

								if cvalue := strings.TrimSpace(config.GetString(rpath+"."+ctype+".provider", "")); cvalue != "" {
									if rule.conditions[ctype] == nil {
										rule.conditions[ctype] = &CONDITION{}
									}
									rule.conditions[ctype].provider = cvalue
								}
								if cvalue := strings.TrimSpace(config.GetString(rpath+"."+ctype+".selector", "")); cvalue != "" {
									if rule.conditions[ctype] == nil {
										rule.conditions[ctype] = &CONDITION{}
									}
									rule.conditions[ctype].selector = strings.ToLower(cvalue)
								}
							}

							for _, rtype := range rtypes {
								if rentry := strings.TrimSpace(config.GetString(rpath+".records."+rtype, "")); rentry != "" {
									if rvalue := parseRecord(rtype, rentry, ttl); rvalue != nil {
										rule.records[rtype] = append(rule.records[rtype], rvalue)
									}
								}
								for _, rpath := range config.GetPaths(rpath + ".records." + rtype) {
									if rentry := strings.TrimSpace(config.GetString(rpath, "")); rentry != "" {
										if rvalue := parseRecord(rtype, rentry, ttl); rvalue != nil {
											rule.records[rtype] = append(rule.records[rtype], rvalue)
										}
									}
								}
							}
							if rule.records != nil {
								rules = append(rules, rule)
							}
						}
						sort.Sort(BYPRIORITY(rules))
						nentries[entry+"."+domain] = rules
					}
				}
			}
		}
		clock.Lock()
		domains = ndomains
		entries = nentries
		clock.Unlock()
	}
}

func loadGeobases() {
	if config != nil {
		bases := []*prefixdb.PrefixDB{}
		for _, path := range config.GetPaths("director.geobases") {
			base := prefixdb.New()
			if err := base.Load(config.GetString(path, "")); err == nil {
				bases = append(bases, base)
			}
		}
		clock.Lock()
		geobases = bases
		clock.Unlock()
		runtime.GC()
	}
}

func reload() {
	loadGeobases()
	for range time.Tick(5 * time.Second) {
		if config != nil {
			trace = config.GetBoolean("director.trace", false)
			changes := false
			for _, path := range config.GetPaths("director.watch") {
				path = strings.TrimSpace(config.GetString(path, ""))
				if info, err := os.Stat(path); err == nil {
					if time.Now().Sub(info.ModTime()) >= 5*time.Second {
						if content, err := ioutil.ReadFile(path); err == nil {
							sum := fmt.Sprintf("%x", sha1.Sum(content))
							if osum, ok := watched[path]; ok {
								if osum != sum {
									changes = true
								}
							}
							watched[path] = sum
						}
					}
				} else {
					watched[path] = ""
				}
			}
			if changes {
				fmt.Fprintf(os.Stderr, "[%d] reloading configuration\n", os.Getpid())
				config.Reload()
				loadCaches()
				loadGeobases()
			}

			if listen := config.GetStringMatch("director.checks.local.listen", "", `^.*?(:\d+)?((,[^,]+){2})?$`); listen != "" {
				go check(listen)
			}
			for _, path := range config.GetPaths("director.checks.remote") {
				go func(name, remote string) {
					client := &http.Client{Timeout: 5 * time.Second}
					if response, err := client.Get(remote); err == nil {
						if body, err := ioutil.ReadAll(response.Body); err == nil {
							result := map[string]CHECK{}
							if json.Unmarshal(body, &result) == nil {
								clock.Lock()
								rchecks[name] = result
								clock.Unlock()
							}
						}
						response.Body.Close()
					}
				}(strings.TrimPrefix(path, "director.checks.remote."), config.GetString(path, ""))
			}
		}
	}
}

func instrings(array []string, search string) bool {
	for _, value := range array {
		if value == search {
			return true
		}
	}
	return false
}
func innets(array []string, address string) bool {
	if ip := net.ParseIP(address); ip != nil {
		for _, value := range array {
			if _, network, err := net.ParseCIDR(value); err == nil {
				if network.Contains(ip) {
					return true
				}
			} else {
				break
			}
		}
	}
	return false
}
func insquares(array []string, lat, lon float64) bool {
	for _, value := range array {
		if matches := sqmatcher.FindStringSubmatch(value); len(matches) >= 5 {
			lat1, _ := strconv.ParseFloat(matches[1], 64)
			lon1, _ := strconv.ParseFloat(matches[2], 64)
			lat2, _ := strconv.ParseFloat(matches[3], 64)
			lon2, _ := strconv.ParseFloat(matches[4], 64)
			if lat >= -180 && lat <= 180 && lon >= -180 && lon <= 180 &&
				lat1 >= -180 && lat1 <= 180 && lon1 >= -180 && lon1 <= 180 &&
				lat2 >= -180 && lat2 <= 180 && lon2 >= -180 && lon2 <= 180 &&
				lat1 > lat2 && lon1 < lon2 &&
				lat1 >= lat && lat >= lat2 && lon1 <= lon && lon <= lon2 {
				return true
			}
		}
	}
	return false
}
func distance(lat1, lon1, lat2, lon2 float64) float64 {
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
func nearest(lat1, lon1 float64, selector string) string {
	max, name := 100000.0, ""
	for _, path := range config.GetPaths(selector) {
		if matches := pmatcher.FindStringSubmatch(config.GetString(path, "")); len(matches) >= 4 {
			lat2, _ := strconv.ParseFloat(matches[1], 64)
			lon2, _ := strconv.ParseFloat(matches[2], 64)
			value := distance(lat1, lon1, lat2, lon2)
			if bias, err := strconv.ParseFloat(matches[3], 64); err == nil {
				if bias > 0 {
					value = value * (1 - (bias / 100))
				} else {
					value = value / (1 + (bias / 100))
				}
			}
			if value < max {
				max, name = value, strings.TrimPrefix(path, selector+".")
			}
		}
	}
	return name
}
func intimes(array []string) bool {
	now := time.Now()
	for _, value := range array {
		for _, predicate := range strings.Split(value, "|") {
			parts := strings.Split(strings.TrimSpace(predicate), " ")
			for index, _ := range parts {
				parts[index] = strings.TrimSpace(parts[index])
			}
			if dmatcher.MatchString(parts[0]) {
				if start, err := time.Parse(time.RFC3339, strings.ToUpper(parts[0])); err != nil {
					return false
				} else if now.Sub(start) < 0 {
					return false
				} else {
					if len(parts) >= 2 {
						if end, err := time.Parse(time.RFC3339, strings.ToUpper(parts[1])); err != nil {
							return false
						} else if now.Sub(end) >= 0 {
							return false
						}
					}
				}
			} else if wmatcher.MatchString(parts[0]) {
				day, matched := weekdays[now.Weekday()], false
				for _, pday := range parts {
					if day == pday {
						matched = true
						break
					}
				}
				if !matched {
					return false
				}
			} else if matches := tmatcher.FindStringSubmatch(parts[0]); matches != nil {
				hours, _ := strconv.Atoi(matches[1])
				minutes, _ := strconv.Atoi(matches[2])
				if (now.UTC().Hour()*60)+now.UTC().Minute() < (hours*60)+minutes {
					return false
				}
				if len(parts) >= 2 {
					if matches := tmatcher.FindStringSubmatch(parts[1]); matches == nil {
						return false
					} else {
						hours, _ := strconv.Atoi(matches[1])
						minutes, _ := strconv.Atoi(matches[2])
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
func passed(array []string) bool {
	if len(rchecks) == 0 {
		return true
	}
	for _, check := range array {
		remote := ""
		if parts := strings.Split(check, "@"); len(parts) > 1 {
			check, remote = parts[0], parts[1]
		}
		if remote != "" {
			if value, ok := rchecks[remote]; !ok {
				continue
			} else {
				if value, ok := value[check]; !ok {
					return true
				} else {
					if value.State == "up" {
						return true
					}
				}
			}
		} else {
			found := false
			for _, value := range rchecks {
				if value, ok := value[check]; ok {
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

func response(qname, rtype string, record *RECORD, rfields map[string]string) {
	line, name := "", record.name
	for key, value := range rfields {
		if key == "cncode" || key == "ccode" || key == "asnum" {
			value = strings.ToUpper(value)
		}
		name = strings.ReplaceAll(name, "{{"+key+"}}", value)
	}
	name = mreplacer.ReplaceAllString(name, "")
	switch rtype {
	case "a", "aaaa", "cname", "ptr":
		line = fmt.Sprintf("DATA\t%s\t1\t%s\tIN\t%s\t%d\t-1\t%s\n", rfields["bits"], qname, strings.ToUpper(rtype), record.ttl, name)
	case "loc": // TODO not implemented yet
	case "mx":
		line = fmt.Sprintf("DATA\t%s\t1\t%s\tIN\tMX\t%d\t-1\t%s\t%s\n", rfields["bits"], qname, record.ttl, record.options[0], name)
	case "srv":
		line = fmt.Sprintf("DATA\t%s\t1\t%s\tIN\tSRV\t%d\t-1\t%s\t%s %s %s\n", rfields["bits"], qname, record.ttl, record.options[0], record.options[1], record.options[2], name)
	case "txt":
		line = fmt.Sprintf("DATA\t%s\t1\t%s\tIN\tTXT\t%d\t-1\t\"%s\"\n", rfields["bits"], qname, record.ttl, strings.ReplaceAll(name, `"`, `\"`))
	}
	if line != "" {
		fmt.Printf("%s", line)
		if trace {
			fmt.Fprintf(os.Stderr, "  %s", line)
		}
	}
}

func lookup(qname, qtype, remote string) {
	clock.RLock()
	if config != nil {
		if trace {
			fmt.Fprintf(os.Stderr, "- %s %s %s\n", qname, qtype, remote)
		}
		if domains[qname] != "" || len(entries[qname]) > 0 {
			domain := qname
			if len(entries[qname]) > 0 {
				domain = strings.SplitN(qname, ".", 2)[1]
			}
			ttl := config.GetIntegerBounds(domains[domain]+".ttl", 600, 10, 86400)
			if qtype == "SOA" || qtype == "ANY" {
				contact := config.GetString(domains[domain]+".contact", "contact@"+domain)
				if index := strings.Index(contact, "@"); index > 0 && index < len(contact)-1 {
					contact = strings.ReplaceAll(contact[:index], ".", `\.`) + "." + contact[index+1:]
				}
				contact = strings.ReplaceAll(contact, "@", ".")
				server := strings.TrimSpace(config.GetString(domains[domain]+".servers.0", "ns."+domain))
				line := fmt.Sprintf("DATA\t0\t1\t%s\tIN\tSOA\t%d\t-1\t%s\t%s\t%s\t86400\t7200\t604800\t172800\n", qname, ttl, server, contact, time.Now().UTC().Format("2006010215"))
				fmt.Printf("%s", line)
				if trace {
					fmt.Fprintf(os.Stderr, "  %s", line)
				}
			}
			if qtype == "NS" || qtype == "ANY" {
				for _, path := range config.GetPaths(domains[domain] + ".servers") {
					if server := strings.TrimSpace(config.GetString(path, "")); server != "" {
						line := fmt.Sprintf("DATA\t0\t1\t%s\tIN\tNS\t%d\t-1\t%s\n", qname, ttl, server)
						fmt.Printf("%s", line)
						if trace {
							fmt.Fprintf(os.Stderr, "  %s", line)
						}
					}
				}
			}

			if len(entries[qname]) > 0 && qtype != "SOA" && qtype != "NS" {
				rfields := map[string]string{"remote": "0.0.0.0", "bits": "32", "identity": config.GetString("director.identity", "")}
				rfields["hostname"], _ = fqdn.FQDN()
				if address, network, err := net.ParseCIDR(remote); err == nil {
					bits, _ := network.Mask.Size()
					rfields["bits"] = fmt.Sprintf("%d", bits)
					rfields["remote"] = fmt.Sprintf("%s", address)
					geoinfo := map[string]interface{}{}
					for _, base := range geobases {
						geoinfo, _ = base.Lookup(address, geoinfo)
					}
					if geoinfo["continent_code"] != nil {
						rfields["continent"] = strings.ToLower(geoinfo["continent_code"].(string))
						rfields["cncode"] = rfields["continent"]
					}
					if geoinfo["continent_name"] != nil {
						rfields["cnname"] = geoinfo["continent_name"].(string)
					}
					if geoinfo["country_code"] != nil {
						rfields["country"] = strings.ToLower(geoinfo["country_code"].(string))
						rfields["ccode"] = rfields["country"]
					}
					if geoinfo["country_name"] != nil {
						rfields["cname"] = geoinfo["country_name"].(string)
					}
					if geoinfo["region_code"] != nil {
						rfields["region"] = strings.ToLower(geoinfo["region_code"].(string))
						rfields["rcode"] = geoinfo["region_code"].(string)
					}
					if geoinfo["region_name"] != nil {
						rfields["rname"] = geoinfo["region_name"].(string)
					}
					if geoinfo["state_code"] != nil {
						rfields["state"] = strings.ToLower(geoinfo["state_code"].(string))
						rfields["scode"] = geoinfo["state_code"].(string)
					}
					if geoinfo["state_name"] != nil {
						rfields["sname"] = geoinfo["state_name"].(string)
					}
					if geoinfo["city_name"] != nil {
						rfields["city"] = geoinfo["city_name"].(string)
					}
					if geoinfo["as_number"] != nil {
						rfields["asnum"] = strings.ToLower(geoinfo["as_number"].(string))
					}
					if geoinfo["as_name"] != nil {
						rfields["asname"] = geoinfo["as_name"].(string)
					}
					if geoinfo["latitude"] != nil {
						rfields["latitude"] = fmt.Sprintf("%f", geoinfo["latitude"].(float64))
						rfields["lat"] = rfields["latitude"]
					}
					if geoinfo["longitude"] != nil {
						rfields["longitude"] = fmt.Sprintf("%f", geoinfo["longitude"].(float64))
						rfields["lon"] = rfields["longitude"]
					}
				}

				records, affinity := map[string][]*RECORD{}, true
				for _, rule := range entries[qname] {
					match := true
					affinity = rule.affinity
					for _, ctype := range ctypes {
						if condition := rule.conditions[ctype]; condition != nil {
							switch ctype {
							case "continent", "country", "region", "state", "asnum", "identity":
								if rfields[ctype] == "" {
									match = false
								} else if (len(condition.include) > 0 && !instrings(condition.include, rfields[ctype])) ||
									(len(condition.exclude) > 0 && instrings(condition.exclude, rfields[ctype])) {
									match = false
								}
							case "cidr":
								if (len(condition.include) > 0 && !innets(condition.include, rfields["remote"])) ||
									(len(condition.exclude) > 0 && innets(condition.exclude, rfields["remote"])) {
									match = false
								}
							case "square", "distance":
								if matches := pmatcher.FindStringSubmatch(rfields["latitude"] + ":" + rfields["longitude"]); len(matches) < 4 {
									match = false
								} else {
									lat, _ := strconv.ParseFloat(matches[1], 64)
									lon, _ := strconv.ParseFloat(matches[2], 64)
									switch ctype {
									case "square":
										if (len(condition.include) > 0 && !insquares(condition.include, lat, lon)) ||
											(len(condition.exclude) > 0 && insquares(condition.exclude, lat, lon)) {
											match = false
										}
									case "distance":
										selector := condition.selector
										if selector[0] == '/' {
											selector = selector[1:]
										} else {
											selector = rule.path + "." + selector
										}
										if name := nearest(lat, lon, selector); name == "" {
											match = false
										} else if (len(condition.include) > 0 && !instrings(condition.include, name)) ||
											(len(condition.exclude) > 0 && instrings(condition.exclude, name)) {
											match = false
										}
									}
								}
							case "time":
								if (len(condition.include) > 0 && !intimes(condition.include)) ||
									(len(condition.exclude) > 0 && intimes(condition.exclude)) {
									match = false
								}
							case "availability":
								if (len(condition.include) > 0 && !passed(condition.include)) ||
									(len(condition.exclude) > 0 && passed(condition.exclude)) {
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
						for rtype, value := range rule.records {
							records[rtype] = append(records[rtype], value...)
						}
						if rule.final {
							break
						}
					}
				}

				for _, rtype := range rtypes {
					if qtype == strings.ToUpper(rtype) || qtype == "ANY" {
						weights, responded := []int{}, false
						for position, record := range records[rtype] {
							if record.weight >= 0 {
								for index := 0; index < record.weight; index++ {
									weights = append(weights, position)
								}
							} else {
								response(qname, rtype, record, rfields)
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
							response(qname, rtype, records[rtype][weights[position]], rfields)
							responded = true
						}
						if responded && rtype == "cname" {
							break
						}
					}
				}
			}
		}
	}

	fmt.Printf("END\n")
	if trace {
		fmt.Fprintf(os.Stderr, "  END\n\n")
	}
	clock.RUnlock()
}

func backend(configuration string) error {
	config, _ = uconfig.New(configuration)
	if config != nil {
		trace = config.GetBoolean("director.trace", false)
		loadCaches()
	}
	go reload()

	reader := bufio.NewReader(os.Stdin)
	for {
		if line, err := reader.ReadString('\n'); err != nil {
			break
		} else {
			fields := strings.Split(strings.TrimSpace(line), "\t")
			if len(fields) == 2 && fields[0] == "HELO" {
				if fields[1] != "3" {
					fmt.Printf("FAIL invalid ABI version %s\n", fields[1])
				} else {
					fmt.Printf("OK [%d] %s/%s ready\n", os.Getpid(), progname, version)
				}
			} else if len(fields) == 8 && fields[0] == "Q" && fields[2] == "IN" {
				lookup(strings.ToLower(fields[1]), fields[3], fields[7])
			} else {
				fmt.Printf("FAIL invalid backend request\n")
			}
		}
	}
	return nil
}
