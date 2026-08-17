//go:build windows

package nucleiprobe

import (
	"os/exec"
	"syscall"
)

// createNoWindow is the Windows CREATE_NO_WINDOW process creation flag. It stops
// the console subsystem from allocating a new visible console window when we
// spawn the nuclei child process, which otherwise flashes a black terminal on
// screen for every scan.
const createNoWindow = 0x08000000

// hideWindow configures cmd so the spawned process does not pop up a console
// window on Windows.
func hideWindow(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.SysProcAttr.CreationFlags |= createNoWindow
}
