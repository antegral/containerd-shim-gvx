//go:build darwin

package fd

func handleArg(raw uintptr) int { return int(raw) }
