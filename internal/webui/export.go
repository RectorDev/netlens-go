package webui

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"netlens/internal/model"
)

func exportName(ext string) string {
	return "netlens-" + time.Now().Format("20060102-150405") + "." + ext
}

func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	flows := s.filtered(r.URL.Query())
	format := strings.ToLower(r.URL.Query().Get("format"))
	switch format {
	case "csv":
		var b bytes.Buffer
		cw := csv.NewWriter(&b)
		_ = cw.Write([]string{"time", "method", "status", "scheme", "host", "url", "process", "pid", "server_ip", "duration_ms", "request_bytes", "response_bytes", "tls", "error"})
		for _, f := range flows {
			_ = cw.Write([]string{f.StartedAt.Format(time.RFC3339Nano), f.Method, strconv.Itoa(f.Status), f.Scheme, f.Host, f.URL, f.ProcessName, strconv.FormatUint(uint64(f.ProcessID), 10), f.ServerIP, strconv.FormatInt(f.DurationMS, 10), strconv.Itoa(f.Request.Bytes), strconv.Itoa(f.Response.Bytes), strconv.FormatBool(f.TLS), f.Error})
		}
		cw.Flush()
		download(w, "text/csv; charset=utf-8", exportName("csv"), b.Bytes())
	case "json":
		b, _ := json.MarshalIndent(flows, "", "  ")
		download(w, "application/json", exportName("json"), b)
	case "har":
		b, _ := json.MarshalIndent(buildHAR(flows), "", "  ")
		download(w, "application/json", exportName("har"), b)
	case "pdf":
		download(w, "application/pdf", exportName("pdf"), buildPDFReport(flows))
	default:
		http.Error(w, "supported formats: csv, json, har, pdf", http.StatusBadRequest)
	}
}

func download(w http.ResponseWriter, contentType, name string, b []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}

func headerPairs(h map[string][]string) []map[string]string {
	out := make([]map[string]string, 0, len(h))
	for k, vals := range h {
		for _, v := range vals {
			out = append(out, map[string]string{"name": k, "value": v})
		}
	}
	return out
}

func buildHAR(flows []*model.Flow) map[string]any {
	entries := make([]map[string]any, 0, len(flows))
	for _, f := range flows {
		u, _ := url.Parse(f.URL)
		query := []map[string]string{}
		if u != nil {
			for k, vals := range u.Query() {
				for _, v := range vals {
					query = append(query, map[string]string{"name": k, "value": v})
				}
			}
		}
		req := map[string]any{
			"method": f.Method, "url": f.URL, "httpVersion": f.Protocol,
			"cookies": []any{}, "headers": headerPairs(f.Request.Headers), "queryString": query,
			"headersSize": -1, "bodySize": f.Request.Bytes,
		}
		if f.Request.Body != "" {
			req["postData"] = map[string]any{"mimeType": firstHeader(f.Request.Headers, "Content-Type"), "text": f.Request.Body}
		}
		res := map[string]any{
			"status": f.Status, "statusText": http.StatusText(f.Status), "httpVersion": f.Protocol,
			"cookies": []any{}, "headers": headerPairs(f.Response.Headers),
			"content":     map[string]any{"size": f.Response.Bytes, "mimeType": firstHeader(f.Response.Headers, "Content-Type"), "text": f.Response.Body},
			"redirectURL": firstHeader(f.Response.Headers, "Location"), "headersSize": -1, "bodySize": f.Response.Bytes,
		}
		entries = append(entries, map[string]any{
			"startedDateTime": f.StartedAt.Format(time.RFC3339Nano), "time": f.DurationMS,
			"request": req, "response": res,
			"cache": map[string]any{}, "timings": map[string]any{"send": 0, "wait": f.DurationMS, "receive": 0},
			"serverIPAddress": f.ServerIP, "connection": strconv.Itoa(f.ClientPort),
			"comment": f.Error,
		})
	}
	return map[string]any{"log": map[string]any{"version": "1.2", "creator": map[string]string{"name": "NetLens", "version": "0.2"}, "entries": entries}}
}

func firstHeader(h map[string][]string, key string) string {
	for k, v := range h {
		if strings.EqualFold(k, key) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}
