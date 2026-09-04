# NetLens Go v0.2.1 Desktop Inspector

NetLens is a Windows-first, system-wide HTTP/HTTPS inspector written in Go. It uses WinDivert to transparently reflect outbound TCP/80 and TCP/443 connections into local listeners, correlates connections with Windows processes, and presents captured requests in a native desktop inspector powered by Microsoft Edge WebView2.

## What's new in v0.2.1

- **Built-in desktop window** using Microsoft Edge WebView2; no normal browser tab is required.
- **Certificate management in the UI**: check status, install/trust, remove, or download the NetLens root CA.
- **Advanced request filters** for text, method, status family, HTTP/HTTPS, process, host, time window, minimum latency, and TLS-only traffic.
- **Much better request table** with sticky headers, sorting, selectable columns, compact transfer sizes, process information, and a responsive inspector pane.
- **Live capture metrics** for visible requests, errors, average/slowest latency, transferred bytes, hosts, and processes.
- **Request detail tabs**: overview, request, response, TLS/security, and developer tools.
- **Developer helpers**: prettified JSON bodies, copy URL, copy flow JSON, and generated cURL commands.
- **Pause/resume recording** without stopping transparent interception.
- **HTTPS request breakpoints**: arm an intercept mode that pauses decrypted HTTPS requests before they are sent upstream. The UI shows a live waiting queue with request headers/body, process and TLS metadata, plus **Continue**, **Drop**, and **Continue all** actions.
- Disabling HTTPS breakpoints automatically continues anything still waiting; forgotten requests also auto-continue after a 5-minute safety timeout.
- **Filtered exports**: CSV, JSON, HAR 1.2, and a standalone PDF report.
- **PDF reports** include capture totals, error counts, byte totals, average latency, top hosts/processes, and a request table.
- **Dark/light theme**, keyboard navigation, column preferences, and in-memory privacy by default.
- UI-changing local API actions require a custom same-origin header to reduce localhost CSRF risk.

## Current capture behavior

- Windows 10/11 x64 first target
- Transparent IPv4 TCP/80 + TCP/443 capture using WinDivert
- HTTP/1.1 request/response headers and bodies
- HTTPS MITM after the NetLens CA is trusted
- PID + executable/path correlation
- In-memory flow store; captured traffic is not persisted unless you explicitly export it
- Default capacity: 5,000 captured flows (`--max-flows` can change it)

## Important limitations

- HTTP/1.1 only. The MITM listener advertises HTTP/1.1 so browsers normally fall back from HTTP/2.
- IPv6 and QUIC/HTTP3 are not intercepted yet. QUIC traffic may need to fall back to TCP before it appears as decryptable HTTP(S).
- Certificate-pinned applications may reject the NetLens certificate.
- Streaming/SSE and WebSocket upgrade handling is still incomplete.
- Transparent Linux capture is not included.
- The WebView2 desktop shell needs the Microsoft Edge WebView2 Runtime, normally present on current Windows 10/11 installations.

## Build on Windows

Install Go 1.23+ and run PowerShell:

```powershell
cd netlens-go
.\scripts\build-windows.ps1
```

The first source build downloads:

1. The official WinDivert 2.2.2 x64 runtime.
2. A pinned `github.com/jchv/go-webview2` source revision and its Go dependencies.

The build creates:

- `netlens.exe` — console/debug build
- `netlens-gui.exe` — desktop GUI build without a console window

Keep `WinDivert.dll` and `WinDivert64.sys` beside the executable.

## Run

Open PowerShell **as Administrator** and use:

```powershell
.\scripts\setup-and-start.ps1
```

NetLens opens its own desktop window. The local inspector server still listens on:

```text
http://127.0.0.1:7788
```

You normally do not need to open that address yourself.

### HTTPS certificate

Open **Settings → HTTPS interception certificate** inside NetLens and choose **Install & Trust CA**. The UI also lets you remove the CA later.

### Pause HTTPS requests before sending

After the CA is trusted, click **HTTPS Break: Off** in the top toolbar to arm request breakpoints. Each decrypted HTTPS request will stop before the upstream connection is made. When a request is waiting, NetLens opens the **Paused HTTPS requests** queue where you can inspect its URL, process, TLS metadata, headers, and body.

- **Continue** — send that request upstream unchanged.
- **Drop** — do not contact the destination; return a local HTTP 403 and record the drop in capture history.
- **Continue all** — release every currently waiting request.
- Turning **HTTPS Break** off releases all pending requests automatically.

A waiting request auto-continues after five minutes as a safety measure so a forgotten breakpoint does not leave an application blocked forever.

CLI compatibility is still available:

```powershell
.\netlens.exe --install-ca
.\netlens.exe --remove-ca
```

## Useful flags

```text
--ui 127.0.0.1:7788   Local inspector address
--max-flows 5000      In-memory flow capacity
--no-window            Run the local inspector without opening WebView2
--debug-ui             Enable WebView2 developer tools
--install-ca           Trust the local NetLens root CA and exit
--remove-ca            Remove the NetLens root CA and exit
```

## Exports

Exports always follow the active UI filters and table sort order.

- **CSV** — compact request table for spreadsheets/data tools
- **JSON** — full NetLens flow objects including headers and display bodies
- **HAR** — browser-tool-compatible HTTP Archive structure
- **PDF** — printable summary report with metrics, top hosts/processes, and request rows

## Architecture

```text
App (unchanged)
   |
   | TCP 80/443
   v
WinDivert network redirector
   |
   +--> HTTP listener :34080 ----+
   |                             |
   +--> TLS MITM listener :34443 |--> recorder/store --> local API :7788
                                 |                         |
                                 |                         +--> WebView2 desktop inspector
                                 |                         +--> filtered CSV/JSON/HAR/PDF
                                 |                         +--> CA install/remove/status
                                 |                         +--> HTTPS breakpoint queue
                                 |                                   |
                                 |                                   +--> Continue / Drop
                                 |
                                 +--> upstream via ALT ports (after Continue)
                                      :43080 -> rewritten to :80
                                      :43443 -> rewritten to :443
```

The ALT ports prevent NetLens's own upstream connections from being intercepted recursively.

## Safety / privacy

Use NetLens only on systems and traffic you own or are authorized to inspect. Captured requests can contain cookies, bearer tokens, API keys, passwords, and personal data. The UI/API binds to localhost by default, and captured flows remain in memory until they are cleared, evicted, the app exits, or you explicitly export them.
