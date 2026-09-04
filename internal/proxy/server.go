package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"netlens/internal/capture"
	"netlens/internal/certmgr"
	"netlens/internal/intercept"
	"netlens/internal/model"
	"netlens/internal/store"
)

const maxDisplayBody = 512 * 1024

type Server struct {
	ca      *certmgr.Manager
	store   *store.Store
	tracker *capture.Tracker
	breaks  *intercept.Manager
	lnHTTP  net.Listener
	lnHTTPS net.Listener
	wg      sync.WaitGroup
}

func New(ca *certmgr.Manager, st *store.Store, tracker *capture.Tracker, breaks *intercept.Manager) *Server {
	return &Server{ca: ca, store: st, tracker: tracker, breaks: breaks}
}

func (s *Server) Start() error {
	var err error
	s.lnHTTP, err = net.Listen("tcp4", fmt.Sprintf(":%d", captureProxyHTTP()))
	if err != nil {
		return err
	}
	s.lnHTTPS, err = net.Listen("tcp4", fmt.Sprintf(":%d", captureProxyHTTPS()))
	if err != nil {
		_ = s.lnHTTP.Close()
		return err
	}
	s.wg.Add(2)
	go s.acceptLoop(s.lnHTTP, false, 80)
	go s.acceptLoop(s.lnHTTPS, true, 443)
	return nil
}

func (s *Server) Close() error {
	if s.lnHTTP != nil {
		_ = s.lnHTTP.Close()
	}
	if s.lnHTTPS != nil {
		_ = s.lnHTTPS.Close()
	}
	s.wg.Wait()
	return nil
}

func captureProxyHTTP() uint16 {
	return 34080
}
func captureProxyHTTPS() uint16 {
	return 34443
}
func captureAltHTTP() uint16  { return 43080 }
func captureAltHTTPS() uint16 { return 43443 }

func (s *Server) acceptLoop(ln net.Listener, isTLS bool, originalPort uint16) {
	defer s.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(c, isTLS, originalPort)
	}
}

func (s *Server) handleConn(raw net.Conn, isTLS bool, originalPort uint16) {
	defer raw.Close()
	remote, ok := raw.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	serverIP := remote.IP.String()
	clientPort := uint16(remote.Port)
	proc := s.tracker.Get(clientPort, originalPort)

	conn := raw
	hostHint := serverIP
	var tlsState *tls.ConnectionState
	if isTLS {
		var sni string
		cfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				sni = hello.ServerName
				h := hello.ServerName
				if h == "" {
					h = serverIP
				}
				der, key, err := s.ca.Leaf(h)
				if err != nil {
					return nil, err
				}
				return &tls.Certificate{Certificate: der, PrivateKey: key}, nil
			},
		}
		t := tls.Server(raw, cfg)
		if err := t.Handshake(); err != nil {
			s.recordTLSFailure(proc, serverIP, int(clientPort), err)
			return
		}
		st := t.ConnectionState()
		tlsState = &st
		if sni != "" {
			hostHint = sni
		}
		conn = t
	}

	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "closed") {
				log.Printf("read request: %v", err)
			}
			return
		}
		if err := s.handleRequest(conn, req, proc, serverIP, int(clientPort), hostHint, isTLS, tlsState); err != nil {
			log.Printf("proxy request error: %v", err)
			return
		}
		if req.Close {
			return
		}
	}
}

func (s *Server) handleRequest(client net.Conn, req *http.Request, proc capture.ProcInfo, serverIP string, clientPort int, hostHint string, isTLS bool, tlsState *tls.ConnectionState) error {
	started := time.Now()
	scheme := "http"
	altPort := captureAltHTTP()
	if isTLS {
		scheme = "https"
		altPort = captureAltHTTPS()
	}
	host := req.Host
	if host == "" {
		host = hostHint
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, fmt.Sprintf("%d", map[bool]int{false: 80, true: 443}[isTLS]))
	}
	cleanHost := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")

	reqBody, err := readAndReset(req.Body)
	if err != nil {
		return err
	}
	req.Body = io.NopCloser(bytes.NewReader(reqBody))
	req.ContentLength = int64(len(reqBody))
	req.RequestURI = ""
	if req.URL == nil {
		req.URL = &url.URL{}
	}
	req.URL.Scheme = scheme
	req.URL.Host = host

	if isTLS && s.breaks != nil && s.breaks.Enabled() {
		paused := model.PausedRequest{
			StartedAt: started, ProcessID: proc.PID, ProcessName: proc.Name, ProcessPath: proc.Path,
			Host: hostOnly(cleanHost), Method: req.Method, URL: req.URL.String(), ServerIP: serverIP, ClientPort: clientPort,
			Request: model.HTTPMessage{Headers: cloneHeader(req.Header), Body: displayBody(reqBody), Bytes: len(reqBody)},
		}
		if tlsState != nil {
			paused.TLSVersion = tlsVersionName(tlsState.Version)
			paused.CipherSuite = tls.CipherSuiteName(tlsState.CipherSuite)
		}
		if s.breaks.Pause(paused) == intercept.Drop {
			return s.dropHTTPSRequest(client, req, proc, serverIP, clientPort, hostOnly(cleanHost), started, tlsState, reqBody)
		}
	}

	dialAddr := net.JoinHostPort(serverIP, fmt.Sprintf("%d", altPort))
	tr := &http.Transport{
		Proxy:              nil,
		DisableCompression: true,
		ForceAttemptHTTP2:  false,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp4", dialAddr)
		},
		TLSClientConfig: &tls.Config{ServerName: hostOnly(cleanHost), MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
	}
	defer tr.CloseIdleConnections()
	resp, roundErr := tr.RoundTrip(req)
	f := &model.Flow{
		ID: s.store.NextID(), StartedAt: started, ProcessID: proc.PID, ProcessName: proc.Name, ProcessPath: proc.Path,
		Protocol: "HTTP/1.1", Scheme: scheme, Host: hostOnly(cleanHost), Method: req.Method, URL: req.URL.String(), ServerIP: serverIP, ClientPort: clientPort, TLS: isTLS,
		Request: model.HTTPMessage{Headers: cloneHeader(req.Header), Body: displayBody(reqBody), Bytes: len(reqBody)},
	}
	if tlsState != nil {
		f.TLSVersion = tlsVersionName(tlsState.Version)
		f.CipherSuite = tls.CipherSuiteName(tlsState.CipherSuite)
	}
	if roundErr != nil {
		f.Error = roundErr.Error()
		f.DurationMS = time.Since(started).Milliseconds()
		s.store.Add(f)
		return roundErr
	}
	respBody, err := readAndReset(resp.Body)
	if err != nil {
		return err
	}
	resp.Body = io.NopCloser(bytes.NewReader(respBody))
	resp.ContentLength = int64(len(respBody))
	f.Status = resp.StatusCode
	f.Response = model.HTTPMessage{Headers: cloneHeader(resp.Header), Body: displayBody(respBody), Bytes: len(respBody)}
	f.DurationMS = time.Since(started).Milliseconds()
	s.store.Add(f)
	resp.Request = req
	if err := resp.Write(client); err != nil {
		return err
	}
	if resp.Close {
		return io.EOF
	}
	return nil
}

func (s *Server) dropHTTPSRequest(client net.Conn, req *http.Request, proc capture.ProcInfo, serverIP string, clientPort int, host string, started time.Time, tlsState *tls.ConnectionState, reqBody []byte) error {
	body := []byte("Request dropped by NetLens HTTPS breakpoint.\n")
	f := &model.Flow{
		ID: s.store.NextID(), StartedAt: started, ProcessID: proc.PID, ProcessName: proc.Name, ProcessPath: proc.Path,
		Protocol: "HTTP/1.1", Scheme: "https", Host: host, Method: req.Method, URL: req.URL.String(), Status: http.StatusForbidden,
		ServerIP: serverIP, ClientPort: clientPort, TLS: true, DurationMS: time.Since(started).Milliseconds(),
		Request:  model.HTTPMessage{Headers: cloneHeader(req.Header), Body: displayBody(reqBody), Bytes: len(reqBody)},
		Response: model.HTTPMessage{Headers: map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}, "X-NetLens-Intercept": {"dropped"}}, Body: string(body), Bytes: len(body)},
		Error:    "Dropped by user during HTTPS interception",
	}
	if tlsState != nil {
		f.TLSVersion = tlsVersionName(tlsState.Version)
		f.CipherSuite = tls.CipherSuiteName(tlsState.CipherSuite)
	}
	s.store.Add(f)
	resp := &http.Response{
		StatusCode: http.StatusForbidden, Status: "403 Forbidden", Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"Content-Type": {"text/plain; charset=utf-8"}, "X-NetLens-Intercept": {"dropped"}},
		Body:   io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Request: req,
	}
	return resp.Write(client)
}

func (s *Server) recordTLSFailure(proc capture.ProcInfo, serverIP string, clientPort int, err error) {
	s.store.Add(&model.Flow{ID: s.store.NextID(), StartedAt: time.Now(), ProcessID: proc.PID, ProcessName: proc.Name, ProcessPath: proc.Path, Protocol: "TLS", Scheme: "https", Host: serverIP, ServerIP: serverIP, ClientPort: clientPort, TLS: true, Error: "TLS interception failed: " + err.Error()})
}

func readAndReset(rc io.ReadCloser) ([]byte, error) {
	if rc == nil {
		return nil, nil
	}
	b, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		return nil, err
	}
	// Caller replaces the body directly because this helper cannot mutate the interface reference.
	return b, nil
}

func cloneHeader(h http.Header) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, v := range h {
		out[k] = append([]string(nil), v...)
	}
	return out
}
func displayBody(b []byte) string {
	if len(b) > maxDisplayBody {
		return string(b[:maxDisplayBody]) + fmt.Sprintf("\n\n[truncated: %d more bytes]", len(b)-maxDisplayBody)
	}
	return string(b)
}
func hostOnly(h string) string {
	if x, _, err := net.SplitHostPort(h); err == nil {
		return x
	}
	return strings.Trim(h, "[]")
}
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}
