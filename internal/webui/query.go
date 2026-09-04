package webui

import (
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"netlens/internal/model"
)

type flowFilter struct {
	Query       string
	Host        string
	Process     string
	Method      string
	Scheme      string
	Status      string
	TLS         string
	MinDuration int64
	From        time.Time
	To          time.Time
	Sort        string
	SortDir     string
}

func parseFlowFilter(v url.Values) flowFilter {
	f := flowFilter{
		Query:   strings.ToLower(strings.TrimSpace(v.Get("q"))),
		Host:    strings.ToLower(strings.TrimSpace(v.Get("host"))),
		Process: strings.ToLower(strings.TrimSpace(v.Get("process"))),
		Method:  strings.ToUpper(strings.TrimSpace(v.Get("method"))),
		Scheme:  strings.ToLower(strings.TrimSpace(v.Get("scheme"))),
		Status:  strings.ToLower(strings.TrimSpace(v.Get("status"))),
		TLS:     strings.ToLower(strings.TrimSpace(v.Get("tls"))),
		Sort:    strings.ToLower(strings.TrimSpace(v.Get("sort"))),
		SortDir: strings.ToLower(strings.TrimSpace(v.Get("sortDir"))),
	}
	f.MinDuration, _ = strconv.ParseInt(v.Get("minDuration"), 10, 64)
	if s := v.Get("from"); s != "" {
		f.From, _ = time.Parse(time.RFC3339, s)
	}
	if s := v.Get("to"); s != "" {
		f.To, _ = time.Parse(time.RFC3339, s)
	}
	return f
}

func filterFlows(flows []*model.Flow, f flowFilter) []*model.Flow {
	out := make([]*model.Flow, 0, len(flows))
	for _, flow := range flows {
		if flow == nil || !matchesFlow(flow, f) {
			continue
		}
		out = append(out, flow)
	}
	sortFlows(out, f.Sort, f.SortDir)
	return out
}

func matchesFlow(x *model.Flow, f flowFilter) bool {
	if f.Query != "" {
		hay := strings.ToLower(strings.Join([]string{
			x.Host, x.URL, x.ProcessName, x.ProcessPath, x.Method, x.Protocol,
			x.ServerIP, x.Error, strconv.Itoa(x.Status),
		}, "\n"))
		if !strings.Contains(hay, f.Query) {
			return false
		}
	}
	if f.Host != "" && strings.ToLower(x.Host) != f.Host {
		return false
	}
	if f.Process != "" && strings.ToLower(x.ProcessName) != f.Process {
		return false
	}
	if f.Method != "" && strings.ToUpper(x.Method) != f.Method {
		return false
	}
	if f.Scheme != "" && strings.ToLower(x.Scheme) != f.Scheme {
		return false
	}
	if f.TLS == "true" && !x.TLS {
		return false
	}
	if f.TLS == "false" && x.TLS {
		return false
	}
	if x.DurationMS < f.MinDuration {
		return false
	}
	if !f.From.IsZero() && x.StartedAt.Before(f.From) {
		return false
	}
	if !f.To.IsZero() && x.StartedAt.After(f.To) {
		return false
	}
	switch f.Status {
	case "success", "2xx":
		return x.Status >= 200 && x.Status < 300
	case "redirect", "3xx":
		return x.Status >= 300 && x.Status < 400
	case "client-error", "4xx":
		return x.Status >= 400 && x.Status < 500
	case "server-error", "5xx":
		return x.Status >= 500 && x.Status < 600
	case "error":
		return x.Error != "" || x.Status >= 400 || x.Status == 0
	case "pending":
		return x.Status == 0 && x.Error == ""
	}
	return true
}

func sortFlows(flows []*model.Flow, field, dir string) {
	if field == "" || field == "time" {
		if dir == "asc" {
			sort.SliceStable(flows, func(i, j int) bool { return flows[i].StartedAt.Before(flows[j].StartedAt) })
		}
		return // store is already newest-first
	}
	less := func(i, j int) bool { return false }
	switch field {
	case "method":
		less = func(i, j int) bool { return flows[i].Method < flows[j].Method }
	case "status":
		less = func(i, j int) bool { return flows[i].Status < flows[j].Status }
	case "host":
		less = func(i, j int) bool { return flows[i].Host < flows[j].Host }
	case "process":
		less = func(i, j int) bool { return flows[i].ProcessName < flows[j].ProcessName }
	case "duration":
		less = func(i, j int) bool { return flows[i].DurationMS < flows[j].DurationMS }
	case "request-bytes":
		less = func(i, j int) bool { return flows[i].Request.Bytes < flows[j].Request.Bytes }
	case "response-bytes":
		less = func(i, j int) bool { return flows[i].Response.Bytes < flows[j].Response.Bytes }
	default:
		return
	}
	sort.SliceStable(flows, func(i, j int) bool {
		v := less(i, j)
		if dir == "desc" {
			return !v && !sameSortValue(flows[i], flows[j], field)
		}
		return v
	})
}

func sameSortValue(a, b *model.Flow, field string) bool {
	switch field {
	case "method":
		return a.Method == b.Method
	case "status":
		return a.Status == b.Status
	case "host":
		return a.Host == b.Host
	case "process":
		return a.ProcessName == b.ProcessName
	case "duration":
		return a.DurationMS == b.DurationMS
	case "request-bytes":
		return a.Request.Bytes == b.Request.Bytes
	case "response-bytes":
		return a.Response.Bytes == b.Response.Bytes
	}
	return false
}
