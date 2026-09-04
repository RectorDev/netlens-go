package model

import "time"

type HTTPMessage struct {
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
	Bytes   int                 `json:"bytes"`
}

type Flow struct {
	ID          uint64      `json:"id"`
	StartedAt   time.Time   `json:"startedAt"`
	DurationMS  int64       `json:"durationMs"`
	ProcessID   uint32      `json:"processId"`
	ProcessName string      `json:"processName"`
	ProcessPath string      `json:"processPath,omitempty"`
	Protocol    string      `json:"protocol"`
	Scheme      string      `json:"scheme"`
	Host        string      `json:"host"`
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	Status      int         `json:"status"`
	ServerIP    string      `json:"serverIp"`
	ClientPort  int         `json:"clientPort"`
	TLS         bool        `json:"tls"`
	TLSVersion  string      `json:"tlsVersion,omitempty"`
	CipherSuite string      `json:"cipherSuite,omitempty"`
	Request     HTTPMessage `json:"request"`
	Response    HTTPMessage `json:"response"`
	Error       string      `json:"error,omitempty"`
}

// PausedRequest is an HTTPS request waiting at an interception breakpoint.
// It deliberately contains request-side data only because no upstream request
// has been made yet.
type PausedRequest struct {
	ID          uint64      `json:"id"`
	StartedAt   time.Time   `json:"startedAt"`
	ProcessID   uint32      `json:"processId"`
	ProcessName string      `json:"processName"`
	ProcessPath string      `json:"processPath,omitempty"`
	Host        string      `json:"host"`
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	ServerIP    string      `json:"serverIp"`
	ClientPort  int         `json:"clientPort"`
	TLSVersion  string      `json:"tlsVersion,omitempty"`
	CipherSuite string      `json:"cipherSuite,omitempty"`
	Request     HTTPMessage `json:"request"`
}
