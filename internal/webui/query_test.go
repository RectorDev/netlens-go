package webui

import (
	"net/url"
	"testing"
	"time"

	"netlens/internal/model"
)

func testFlow(id uint64, host, method string, status int, tls bool, ms int64) *model.Flow {
	return &model.Flow{ID: id, StartedAt: time.Now(), Host: host, Method: method, Status: status, TLS: tls, Scheme: map[bool]string{true: "https", false: "http"}[tls], DurationMS: ms, ProcessName: "browser.exe", URL: "https://" + host + "/api"}
}

func TestFilterFlows(t *testing.T) {
	flows := []*model.Flow{
		testFlow(1, "api.example.com", "GET", 200, true, 40),
		testFlow(2, "api.example.com", "POST", 500, true, 900),
		testFlow(3, "plain.example.com", "GET", 404, false, 120),
	}
	v := url.Values{}
	v.Set("host", "api.example.com")
	v.Set("status", "error")
	v.Set("tls", "true")
	v.Set("minDuration", "500")
	out := filterFlows(flows, parseFlowFilter(v))
	if len(out) != 1 || out[0].ID != 2 {
		t.Fatalf("unexpected filtered flows: %#v", out)
	}
}

func TestPDFReport(t *testing.T) {
	flows := []*model.Flow{testFlow(1, "api.example.com", "GET", 200, true, 42)}
	b := buildPDFReport(flows)
	if len(b) < 200 {
		t.Fatalf("PDF too small: %d", len(b))
	}
	if string(b[:5]) != "%PDF-" {
		t.Fatalf("missing PDF header")
	}
	if string(b[len(b)-6:]) != "%%EOF\n" {
		t.Fatalf("missing PDF EOF")
	}
}
