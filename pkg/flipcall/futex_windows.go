//go:build windows

package flipcall

import (
	"fmt"
	"runtime"
)

func (ep *Endpoint) futexSetPeerActive() error {
	if ep.connState().CompareAndSwap(ep.activeState, ep.inactiveState) {
		return nil
	}
	switch cs := ep.connState().Load(); cs {
	case csShutdown:
		return ShutdownError{}
	default:
		return fmt.Errorf("unexpected connection state before wake: %v", cs)
	}
}

func (ep *Endpoint) futexWakePeer() error {
	return ep.futexWakeConnState(1)
}

func (ep *Endpoint) futexWakeConnState(_ int32) error {
	return nil
}

func (ep *Endpoint) futexWaitConnState(_ uint32) error {
	runtime.Gosched()
	return nil
}

func (ep *Endpoint) futexWaitUntilActive() error {
	for {
		switch cs := ep.connState().Load(); cs {
		case ep.activeState:
			return nil
		case ep.inactiveState:
			if ep.isShutdownLocally() {
				return ShutdownError{}
			}
			runtime.Gosched()
		case csShutdown:
			return ShutdownError{}
		default:
			return fmt.Errorf("unexpected connection state during wait: %v", cs)
		}
	}
}

func yieldThread() {
	runtime.Gosched()
}
