package main

import (
	"fmt"
	"sync"

	"github.com/DataDog/datadog-go/statsd"
)

var (
	metricsSession *statsd.Client
	metricsLock    sync.Mutex
)

func metricsLink() *statsd.Client {
	if metricsSession == nil && len(config.GetPaths("director.metrics")) > 0 {
		metricsLock.Lock()
		if metricsSession == nil {
			if metricsSession, _ = statsd.New(config.GetString("director.metrics.server", "127.0.0.1:8125")); metricsSession != nil {
				metricsSession.Namespace = config.GetString("director.metrics.base", "nsdirector") + "."
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
			stags = append(stags, fmt.Sprintf("%s:%v", key, value))
		}
	}
	return stags
}

func metricsGauge(metric string, value int64, tags map[string]interface{}) {
	if session := metricsLink(); session != nil {
		session.Gauge(metric, float64(value), metricsTags(tags), 1)
	}
}

func metricsCount(metric string, value int64, tags map[string]interface{}) {
	if session := metricsLink(); session != nil {
		session.Count(metric, value, metricsTags(tags), 1)
	}
}

func metricsHistogram(metric string, value int64, tags map[string]interface{}) {
	if session := metricsLink(); session != nil {
		session.Histogram(metric, float64(value), metricsTags(tags), 1)
	}
}

func metricsEvent(title string, text string) {
	if session := metricsLink(); session != nil {
		event := statsd.NewEvent(title, text)
		session.Event(event)
	}
}
