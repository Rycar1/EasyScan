//go:build !windows

package nucleiprobe

import "os/exec"

// hideWindow is a no-op on non-Windows platforms, where spawning a child
// process does not create a visible console window.
func hideWindow(cmd *exec.Cmd) {}
