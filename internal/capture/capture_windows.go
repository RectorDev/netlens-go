//go:build windows

package capture

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"

	"netlens/internal/windivert"
)

const (
	ProxyHTTP  uint16 = 34080
	AltHTTP    uint16 = 43080
	ProxyHTTPS uint16 = 34443
	AltHTTPS   uint16 = 43443
)

type windowsService struct {
	tracker   *Tracker
	network   windivert.Handle
	flow      windivert.Handle
	wg        sync.WaitGroup
	closeOnce sync.Once
}

func New(tracker *Tracker) (Service, error) {
	filter := fmt.Sprintf("ip and tcp and (tcp.DstPort == 80 or tcp.DstPort == 443 or tcp.DstPort == %d or tcp.DstPort == %d or tcp.DstPort == %d or tcp.DstPort == %d or tcp.SrcPort == 80 or tcp.SrcPort == 443 or tcp.SrcPort == %d or tcp.SrcPort == %d)", ProxyHTTP, ProxyHTTPS, AltHTTP, AltHTTPS, ProxyHTTP, ProxyHTTPS)
	n, err := windivert.Open(filter, windivert.LayerNetwork, 123, 0)
	if err != nil {
		return nil, fmt.Errorf("open WinDivert network handle (run as Administrator and keep WinDivert.dll/WinDivert64.sys beside netlens.exe): %w", err)
	}
	f, err := windivert.Open("outbound and tcp and (remotePort == 80 or remotePort == 443)", windivert.LayerFlow, 124, windivert.FlagSniff|windivert.FlagRecvOnly)
	if err != nil {
		_ = n.Close()
		return nil, fmt.Errorf("open WinDivert flow handle: %w", err)
	}
	return &windowsService{tracker: tracker, network: n, flow: f}, nil
}

func bswap16(v uint16) uint16 { return v<<8 | v>>8 }
func htons(v uint16) uint16   { return bswap16(v) }
func ntohs(v uint16) uint16   { return bswap16(v) }

func (s *windowsService) Run(ctx context.Context) error {
	errCh := make(chan error, 2)
	s.wg.Add(2)
	go func() { defer s.wg.Done(); errCh <- s.runFlows(ctx) }()
	go func() { defer s.wg.Done(); errCh <- s.runRedirect(ctx) }()
	select {
	case <-ctx.Done():
		_ = s.Close()
		s.wg.Wait()
		return nil
	case err := <-errCh:
		_ = s.Close()
		return err
	}
}

func (s *windowsService) Close() error {
	var err error
	s.closeOnce.Do(func() {
		if s.network != 0 {
			err = s.network.Close()
		}
		if s.flow != 0 {
			_ = s.flow.Close()
		}
	})
	return err
}

func (s *windowsService) runFlows(ctx context.Context) error {
	for {
		var addr windivert.Address
		_, err := s.flow.Recv(nil, &addr)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		fl := addr.Flow()
		lp, rp := fl.LocalPort, fl.RemotePort
		if rp != 80 && rp != 443 {
			continue
		}
		switch addr.Event() {
		case 1: // WINDIVERT_EVENT_FLOW_ESTABLISHED
			name, path := processName(fl.ProcessID)
			s.tracker.Put(lp, rp, ProcInfo{PID: fl.ProcessID, Name: name, Path: path})
		case 2: // WINDIVERT_EVENT_FLOW_DELETED
			s.tracker.Delete(lp, rp)
		}
	}
}

func (s *windowsService) runRedirect(ctx context.Context) error {
	buf := make([]byte, 65535)
	for {
		var addr windivert.Address
		n, err := s.network.Recv(buf, &addr)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		packet := buf[:n]
		ipOff, tcpOff, ok := ipv4TCP(packet)
		if !ok {
			_, _ = s.network.Send(packet, &addr)
			continue
		}
		srcPort := ntohs(*(*uint16)(unsafe.Pointer(&packet[tcpOff])))
		dstPort := ntohs(*(*uint16)(unsafe.Pointer(&packet[tcpOff+2])))
		if addr.Outbound() {
			switch {
			case dstPort == 80:
				reflectToProxy(packet, ipOff, tcpOff, &addr, ProxyHTTP)
			case dstPort == 443:
				reflectToProxy(packet, ipOff, tcpOff, &addr, ProxyHTTPS)
			case srcPort == ProxyHTTP:
				reflectFromProxy(packet, ipOff, tcpOff, &addr, 80)
			case srcPort == ProxyHTTPS:
				reflectFromProxy(packet, ipOff, tcpOff, &addr, 443)
			case dstPort == AltHTTP:
				put16(packet[tcpOff+2:], htons(80))
			case dstPort == AltHTTPS:
				put16(packet[tcpOff+2:], htons(443))
			}
		} else {
			switch srcPort {
			case 80:
				put16(packet[tcpOff:], htons(AltHTTP))
			case 443:
				put16(packet[tcpOff:], htons(AltHTTPS))
			}
		}
		windivert.CalcChecksums(packet, &addr)
		if _, err := s.network.Send(packet, &addr); err != nil {
			return err
		}
	}
}

func ipv4TCP(p []byte) (ipOff, tcpOff int, ok bool) {
	if len(p) < 40 || p[0]>>4 != 4 || p[9] != 6 {
		return 0, 0, false
	}
	ihl := int(p[0]&0x0f) * 4
	if ihl < 20 || len(p) < ihl+20 {
		return 0, 0, false
	}
	return 0, ihl, true
}
func get32(b []byte) uint32    { return *(*uint32)(unsafe.Pointer(&b[0])) }
func put32(b []byte, v uint32) { *(*uint32)(unsafe.Pointer(&b[0])) = v }
func put16(b []byte, v uint16) { *(*uint16)(unsafe.Pointer(&b[0])) = v }

func reflectToProxy(p []byte, ipOff, tcpOff int, addr *windivert.Address, proxyPort uint16) {
	src := get32(p[ipOff+12:])
	dst := get32(p[ipOff+16:])
	put16(p[tcpOff+2:], htons(proxyPort))
	put32(p[ipOff+12:], dst)
	put32(p[ipOff+16:], src)
	addr.SetOutbound(false)
}
func reflectFromProxy(p []byte, ipOff, tcpOff int, addr *windivert.Address, originalPort uint16) {
	src := get32(p[ipOff+12:])
	dst := get32(p[ipOff+16:])
	put16(p[tcpOff:], htons(originalPort))
	put32(p[ipOff+12:], dst)
	put32(p[ipOff+16:], src)
	addr.SetOutbound(false)
}

var (
	kernel32                   = syscall.NewLazyDLL("kernel32.dll")
	queryFullProcessImageNameW = kernel32.NewProc("QueryFullProcessImageNameW")
)

func processName(pid uint32) (string, string) {
	const processQueryLimitedInformation = 0x1000
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, pid)
	if err != nil {
		return fmt.Sprintf("PID %d", pid), ""
	}
	defer syscall.CloseHandle(h)
	buf := make([]uint16, 32768)
	n := uint32(len(buf))
	r1, _, _ := queryFullProcessImageNameW.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
	if r1 == 0 {
		return fmt.Sprintf("PID %d", pid), ""
	}
	p := syscall.UTF16ToString(buf[:n])
	return filepath.Base(p), p
}
