//go:build windows

package syserr

import (
	"fmt"

	"golang.org/x/sys/unix"
)

const maxErrno = 256

var windowsHostTranslations [maxErrno]*Error

func getHostTranslation(err unix.Errno) *Error {
	if uint64(err) >= uint64(len(windowsHostTranslations)) {
		return nil
	}
	return windowsHostTranslations[err]
}

func addHostTranslation(host unix.Errno, trans *Error) {
	if uint64(host) >= uint64(len(windowsHostTranslations)) {
		return
	}
	if windowsHostTranslations[host] != nil {
		panic(fmt.Sprintf("duplicate translation for host errno %q (%d)", host.Error(), host))
	}
	windowsHostTranslations[host] = trans
}
