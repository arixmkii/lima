package store

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/lima-vm/lima/pkg/executil"
	"github.com/lima-vm/lima/pkg/limayaml"
)

func inspectStatus(instDir string, inst *Instance, y *limayaml.LimaYAML) {
	if inst.VMType == limayaml.WSL2 {
		status, err := GetWslStatus(inst.Name)
		if err != nil {
			inst.Status = StatusBroken
			inst.Errors = append(inst.Errors, err)
		} else {
			inst.Status = status
		}

		inst.SSHLocalPort = 22

		if inst.Status == StatusRunning {
			sshAddr, err := GetSSHAddress(inst.Name)
			if err == nil {
				inst.SSHAddress = sshAddr
			} else {
				inst.Errors = append(inst.Errors, err)
			}
		}
	} else {
		inspectStatusWithPIDFiles(instDir, inst, y)
	}
}

// GetWslStatus runs `wsl --list --verbose` and parses its output.
// There are several possible outputs, all listed with their whitespace preserved output below.
//
// (1) Expected output if at least one distro is installed:
// PS > wsl --list --verbose
//
//	NAME      STATE           VERSION
//
// * Ubuntu    Stopped         2
//
// (2) Expected output when no distros are installed, but WSL is configured properly:
// PS > wsl --list --verbose
// Windows Subsystem for Linux has no installed distributions.
//
// Use 'wsl.exe --list --online' to list available distributions
// and 'wsl.exe --install <Distro>' to install.
//
// Distributions can also be installed by visiting the Microsoft Store:
// https://aka.ms/wslstore
// Error code: Wsl/WSL_E_DEFAULT_DISTRO_NOT_FOUND
//
// (3) Expected output when no distros are installed, and WSL2 has no kernel installed:
//
// PS > wsl --list --verbose
// Windows Subsystem for Linux has no installed distributions.
// Distributions can be installed by visiting the Microsoft Store:
// https://aka.ms/wslstore
func GetWslStatus(instName string) (string, error) {
	distroName := "lima-" + instName
	out, err := executil.RunUTF16leCommand([]string{
		"wsl.exe",
		"--list",
		"--verbose",
	})
	if err != nil {
		return "", fmt.Errorf("failed to run `wsl --list --verbose`, err: %w (out=%q)", err, string(out))
	}

	if len(out) == 0 {
		return StatusBroken, fmt.Errorf("failed to read instance state for instance %q, try running `wsl --list --verbose` to debug, err: %w", instName, err)
	}

	// Check for edge cases first
	outString := string(out)
	if strings.Contains(outString, "Windows Subsystem for Linux has no installed distributions.") {
		if strings.Contains(outString, "Wsl/WSL_E_DEFAULT_DISTRO_NOT_FOUND") {
			return StatusBroken, fmt.Errorf(
				"failed to read instance state for instance %q because no distro is installed,"+
					"try running `wsl --install -d Ubuntu` and then re-running Lima", instName)
		}
		return StatusBroken, fmt.Errorf(
			"failed to read instance state for instance %q because there is no WSL kernel installed,"+
				"this usually happens when WSL was installed for another user, but never for your user."+
				"Try running `wsl --install -d Ubuntu` and `wsl --update`, and then re-running Lima", instName)
	}

	var instState string
	wslListColsRegex := regexp.MustCompile(`\s+`)
	// wsl --list --verbose may have different headers depending on localization, just split by line
	for _, rows := range strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n") {
		cols := wslListColsRegex.Split(strings.TrimSpace(rows), -1)
		nameIdx := 0
		// '*' indicates default instance
		if cols[0] == "*" {
			nameIdx = 1
		}
		if cols[nameIdx] == distroName {
			instState = cols[nameIdx+1]
			break
		}
	}

	if instState == "" {
		return StatusUninitialized, nil
	}

	return instState, nil
}

func GetSSHAddress(instName string) (string, error) {
	return "127.0.0.1", nil
}
