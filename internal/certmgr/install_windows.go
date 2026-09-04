//go:build windows

package certmgr

import (
	"fmt"
	"os/exec"
	"strings"
)

func InstallRootCertificate(m *Manager) error {
	if installed, _ := RootCertificateInstalled(m); installed {
		return nil
	}
	cmd := exec.Command("certutil.exe", "-user", "-addstore", "Root", m.CertDERPath())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("certutil failed: %w: %s", err, string(out))
	}
	return nil
}

func RemoveRootCertificate(m *Manager) error {
	if installed, _ := RootCertificateInstalled(m); !installed {
		return nil
	}
	cmd := exec.Command("certutil.exe", "-user", "-delstore", "Root", "NetLens Local Root CA")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("certutil failed: %w: %s", err, string(out))
	}
	return nil
}

func RootCertificateInstalled(m *Manager) (bool, error) {
	// Listing the store and searching for our stable Common Name avoids depending
	// on localized certutil "not found" error text.
	cmd := exec.Command("certutil.exe", "-user", "-store", "Root")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("certutil status failed: %w: %s", err, string(out))
	}
	return strings.Contains(string(out), "NetLens Local Root CA"), nil
}
