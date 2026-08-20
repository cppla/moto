//go:build windows

package main

import "os"

// Windows has no SIGHUP-equivalent in Moto's service lifecycle. Returning a
// nil channel disables the reload select case without a polling goroutine.
func notifyReloadSignals() (<-chan os.Signal, func()) {
	return nil, func() {}
}
