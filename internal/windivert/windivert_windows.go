//go:build windows

package windivert

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	LayerNetwork = 0
	LayerFlow    = 2
	FlagSniff    = 0x0001
	FlagRecvOnly = 0x0004
)

var (
	dll    = syscall.NewLazyDLL("WinDivert.dll")
	pOpen  = dll.NewProc("WinDivertOpen")
	pRecv  = dll.NewProc("WinDivertRecv")
	pSend  = dll.NewProc("WinDivertSend")
	pClose = dll.NewProc("WinDivertClose")
	pCalc  = dll.NewProc("WinDivertHelperCalcChecksums")
)

type Handle uintptr

type Address struct {
	Timestamp int64
	Bits      uint64
	Data      [64]byte
}

type FlowData struct {
	EndpointID       uint64
	ParentEndpointID uint64
	ProcessID        uint32
	LocalAddr        [4]uint32
	RemoteAddr       [4]uint32
	LocalPort        uint16
	RemotePort       uint16
	Protocol         uint8
	_                [7]byte
}

func (a *Address) Event() uint8   { return uint8((a.Bits >> 8) & 0xff) }
func (a *Address) Outbound() bool { return (a.Bits & (1 << 17)) != 0 }
func (a *Address) SetOutbound(v bool) {
	if v {
		a.Bits |= 1 << 17
	} else {
		a.Bits &^= 1 << 17
	}
}
func (a *Address) Flow() *FlowData { return (*FlowData)(unsafe.Pointer(&a.Data[0])) }

func Open(filter string, layer uint32, priority int16, flags uint64) (Handle, error) {
	p, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return 0, err
	}
	r1, _, e1 := pOpen.Call(uintptr(unsafe.Pointer(p)), uintptr(layer), uintptr(uint16(priority)), uintptr(flags))
	if r1 == ^uintptr(0) || r1 == 0 {
		if e1 != syscall.Errno(0) {
			return 0, e1
		}
		return 0, fmt.Errorf("WinDivertOpen failed")
	}
	return Handle(r1), nil
}

func (h Handle) Close() error {
	if h == 0 {
		return nil
	}
	r1, _, e1 := pClose.Call(uintptr(h))
	if r1 == 0 && e1 != syscall.Errno(0) {
		return e1
	}
	return nil
}

func (h Handle) Recv(buf []byte, addr *Address) (uint32, error) {
	var recvLen uint32
	var ptr uintptr
	if len(buf) > 0 {
		ptr = uintptr(unsafe.Pointer(&buf[0]))
	}
	r1, _, e1 := pRecv.Call(uintptr(h), ptr, uintptr(len(buf)), uintptr(unsafe.Pointer(&recvLen)), uintptr(unsafe.Pointer(addr)))
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			return 0, e1
		}
		return 0, fmt.Errorf("WinDivertRecv failed")
	}
	return recvLen, nil
}

func (h Handle) Send(buf []byte, addr *Address) (uint32, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	var sendLen uint32
	r1, _, e1 := pSend.Call(uintptr(h), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&sendLen)), uintptr(unsafe.Pointer(addr)))
	if r1 == 0 {
		if e1 != syscall.Errno(0) {
			return 0, e1
		}
		return 0, fmt.Errorf("WinDivertSend failed")
	}
	return sendLen, nil
}

func CalcChecksums(buf []byte, addr *Address) {
	if len(buf) == 0 {
		return
	}
	_, _, _ = pCalc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(addr)), 0)
}
