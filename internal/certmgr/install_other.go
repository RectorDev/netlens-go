//go:build !windows

package certmgr

import "fmt"

func InstallRootCertificate(m *Manager) error {
	return fmt.Errorf("automatic CA installation is only implemented on Windows")
}
func RemoveRootCertificate(m *Manager) error {
	return fmt.Errorf("automatic CA removal is only implemented on Windows")
}
func RootCertificateInstalled(m *Manager) (bool, error) {
	return false, fmt.Errorf("automatic CA status is only implemented on Windows")
}
