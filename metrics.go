package main

import (
	"fmt"
	"sync"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/pyke369/golang-support/rcache"
)

var (
	metricsSession *statsd.Client
	metricsLock    sync.Mutex
)

func metricsLink() *statsd.Client {
	if metricsSession == nil && len(config.GetPaths(progname+".metrics")) > 0 {
		metricsLock.Lock()
		if metricsSession == nil {
			if metricsSession, _ = statsd.New(config.GetString(progname+".metrics.server", "127.0.0.1:8125")); metricsSession != nil {
				metricsSession.Namespace = config.GetString(progname+".metrics.base", progname) + "."
			}
		}
		metricsLock.Unlock()
	}
	return metricsSession
}

func metricsTags(tags map[string]interface{}) []string {
	stags := []string{}
	if tags != nil {
		for key, value := range tags {
			svalue := fmt.Sprintf("%v", value)
			if filter := config.GetString(progname+".metrics.filters."+key, ""); filter != "" {
				if matcher := rcache.Get(filter); matcher != nil && !matcher.MatchString(svalue) {
					if svalue != "" {
						svalue = "other"
					}
				}
			}
			stags = append(stags, fmt.Sprintf("%s:%s", key, svalue))
		}
	}
	return stags
}

func MetricsGauge(metric string, value int64, tags map[string]interface{}) {
	if session := metricsLink(); session != nil {
		session.Gauge(metric, float64(value), metricsTags(tags), 1)
	}
}

func MetricsCount(metric string, value int64, tags map[string]interface{}) {
	if session := metricsLink(); session != nil {
		session.Count(metric, value, metricsTags(tags), 1)
	}
}

func MetricsHistogram(metric string, value int64, tags map[string]interface{}) {
	if session := metricsLink(); session != nil {
		session.Histogram(metric, float64(value), metricsTags(tags), 1)
	}
}

func MetricsEvent(title string, text string) {
	if session := metricsLink(); session != nil {
		event := statsd.NewEvent(title, text)
		session.Event(event)
	}
}
