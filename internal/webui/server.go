package webui

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"netlens/internal/certmgr"
	"netlens/internal/intercept"
	"netlens/internal/model"
	"netlens/internal/store"
)

//go:embed index.html
var indexHTML string

type Server struct {
	st     *store.Store
	ca     *certmgr.Manager
	breaks *intercept.Manager
	addr   string
	http   *http.Server
	ln     net.Listener
}

func New(st *store.Store, ca *certmgr.Manager, breaks *intercept.Manager, addr string) *Server {
	return &Server{st: st, ca: ca, breaks: breaks, addr: addr}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		_, _ = w.Write([]byte(indexHTML))
	})
	mux.HandleFunc("/api/flows", s.flows)
	mux.HandleFunc("/api/flows/", s.flow)
	mux.HandleFunc("/api/stats", s.stats)
	mux.HandleFunc("/api/clear", s.uiAction(s.clear))
	mux.HandleFunc("/api/recording", s.uiAction(s.recording))
	mux.HandleFunc("/api/intercept", s.interceptRoot)
	mux.HandleFunc("/api/intercept/pending", s.interceptPending)
	mux.HandleFunc("/api/intercept/continue-all", s.uiAction(s.interceptContinueAll))
	mux.HandleFunc("/api/intercept/", s.uiAction(s.interceptDecision))
	mux.HandleFunc("/api/status", s.status)
	mux.HandleFunc("/api/cert", s.certStatus)
	mux.HandleFunc("/api/cert/install", s.uiAction(s.certInstall))
	mux.HandleFunc("/api/cert/remove", s.uiAction(s.certRemove))
	mux.HandleFunc("/api/cert/download", s.certDownload)
	mux.HandleFunc("/api/export", s.export)

	s.http = &http.Server{Addr: s.addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.ln = ln
	go func() { _ = s.http.Serve(ln) }()
	return nil
}

func (s *Server) Close() error {
	if s.http == nil {
		return nil
	}
	return s.http.Close()
}
func (s *Server) URL() string { return fmt.Sprintf("http://%s", s.addr) }

func jsonOut(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) isUIAction(r *http.Request) bool {
	if r.Method != http.MethodPost || r.Header.Get("X-NetLens-UI") != "1" {
		return false
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

func (s *Server) uiAction(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !s.isUIAction(r) {
			http.Error(w, "localhost UI action header required", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (s *Server) filtered(v url.Values) []*model.Flow {
	f := parseFlowFilter(v)
	return filterFlows(s.st.List(0), f)
}

func (s *Server) filteredQuery(r *http.Request) []*model.Flow { return s.filtered(r.URL.Query()) }

func (s *Server) flows(w http.ResponseWriter, r *http.Request) {
	flows := s.filteredQuery(r)
	lim, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if lim <= 0 {
		lim = 1000
	}
	if lim < len(flows) {
		flows = flows[:lim]
	}
	jsonOut(w, flows)
}
func (s *Server) flow(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(strings.TrimPrefix(r.URL.Path, "/api/flows/"), 10, 64)
	f, ok := s.st.Get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	jsonOut(w, f)
}
func (s *Server) clear(w http.ResponseWriter, r *http.Request) {
	s.st.Clear()
	jsonOut(w, map[string]bool{"ok": true})
}
func (s *Server) recording(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Recording bool `json:"recording"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	s.st.SetRecording(body.Recording)
	jsonOut(w, map[string]any{"ok": true, "recording": s.st.Recording()})
}
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	installed, _ := certmgr.RootCertificateInstalled(s.ca)
	interceptEnabled, pending := false, 0
	if s.breaks != nil {
		interceptEnabled = s.breaks.Enabled()
		pending = s.breaks.PendingCount()
	}
	jsonOut(w, map[string]any{"capturing": s.st.Recording(), "flows": s.st.Count(), "maxFlows": s.st.MaxFlows(), "ui": s.URL(), "caInstalled": installed, "ca": s.ca.RootSummary(), "httpsPauseEnabled": interceptEnabled, "pausedHTTPS": pending})
}

func (s *Server) interceptRoot(w http.ResponseWriter, r *http.Request) {
	if s.breaks == nil {
		http.Error(w, "HTTPS breakpoints unavailable", http.StatusNotImplemented)
		return
	}
	if r.Method == http.MethodGet {
		jsonOut(w, map[string]any{"enabled": s.breaks.Enabled(), "pending": s.breaks.PendingCount()})
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.isUIAction(r) {
		http.Error(w, "localhost UI action header required", http.StatusForbidden)
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	s.breaks.SetEnabled(body.Enabled)
	jsonOut(w, map[string]any{"ok": true, "enabled": s.breaks.Enabled(), "pending": s.breaks.PendingCount()})
}

func (s *Server) interceptPending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.breaks == nil {
		jsonOut(w, []model.PausedRequest{})
		return
	}
	jsonOut(w, s.breaks.List())
}

func (s *Server) interceptDecision(w http.ResponseWriter, r *http.Request) {
	if s.breaks == nil {
		http.Error(w, "HTTPS breakpoints unavailable", http.StatusNotImplemented)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/intercept/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		http.Error(w, "invalid request id", http.StatusBadRequest)
		return
	}
	d := intercept.Continue
	switch parts[1] {
	case "continue":
		d = intercept.Continue
	case "drop":
		d = intercept.Drop
	default:
		http.NotFound(w, r)
		return
	}
	if !s.breaks.Resolve(id, d) {
		http.Error(w, "request is no longer pending", http.StatusNotFound)
		return
	}
	jsonOut(w, map[string]any{"ok": true, "id": id, "decision": d})
}

func (s *Server) interceptContinueAll(w http.ResponseWriter, r *http.Request) {
	if s.breaks == nil {
		http.Error(w, "HTTPS breakpoints unavailable", http.StatusNotImplemented)
		return
	}
	jsonOut(w, map[string]any{"ok": true, "continued": s.breaks.ResolveAll(intercept.Continue)})
}
func (s *Server) certStatus(w http.ResponseWriter, r *http.Request) {
	installed, err := certmgr.RootCertificateInstalled(s.ca)
	jsonOut(w, map[string]any{"installed": installed, "summary": s.ca.RootSummary(), "path": s.ca.CertPath(), "error": errString(err)})
}
func (s *Server) certInstall(w http.ResponseWriter, r *http.Request) {
	if err := certmgr.InstallRootCertificate(s.ca); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOut(w, map[string]any{"ok": true, "installed": true, "summary": s.ca.RootSummary()})
}
func (s *Server) certRemove(w http.ResponseWriter, r *http.Request) {
	if err := certmgr.RemoveRootCertificate(s.ca); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOut(w, map[string]any{"ok": true, "installed": false})
}
func (s *Server) certDownload(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, s.ca.CertDERPath())
}
func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	flows := s.filteredQuery(r)
	jsonOut(w, calculateStats(flows))
}

func calculateStats(flows []*model.Flow) map[string]any {
	var reqBytes, resBytes int
	var duration int64
	errors := 0
	hosts := map[string]int{}
	procs := map[string]int{}
	statuses := map[string]int{"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0}
	for _, f := range flows {
		reqBytes += f.Request.Bytes
		resBytes += f.Response.Bytes
		duration += f.DurationMS
		if f.Error != "" || f.Status >= 400 || f.Status == 0 {
			errors++
		}
		if f.Host != "" {
			hosts[f.Host]++
		}
		p := f.ProcessName
		if p == "" {
			p = "unknown"
		}
		procs[p]++
		switch {
		case f.Status >= 200 && f.Status < 300:
			statuses["2xx"]++
		case f.Status >= 300 && f.Status < 400:
			statuses["3xx"]++
		case f.Status >= 400 && f.Status < 500:
			statuses["4xx"]++
		case f.Status >= 500 && f.Status < 600:
			statuses["5xx"]++
		default:
			statuses["other"]++
		}
	}
	avg := int64(0)
	if len(flows) > 0 {
		avg = duration / int64(len(flows))
	}
	return map[string]any{"count": len(flows), "errors": errors, "requestBytes": reqBytes, "responseBytes": resBytes, "avgDurationMs": avg, "hosts": hosts, "processes": procs, "statuses": statuses}
}
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
