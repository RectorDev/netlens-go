//go:build windows

package desktop

import (
	"fmt"

	webview2 "github.com/jchv/go-webview2"
)

func Run(url string, debug bool) error {
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     debug,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:  "NetLens Network Inspector",
			Width:  1480,
			Height: 920,
			Center: true,
		},
	})
	if w == nil {
		return fmt.Errorf("failed to initialize Microsoft Edge WebView2")
	}
	defer w.Destroy()
	w.SetSize(1120, 720, webview2.HintMin)
	w.Navigate(url)
	w.Run()
	return nil
}
