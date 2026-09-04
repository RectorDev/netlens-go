//go:build !windows

package desktop

import "fmt"

func Run(url string, debug bool) error {
	return fmt.Errorf("embedded WebView2 desktop UI is currently available on Windows only")
}
