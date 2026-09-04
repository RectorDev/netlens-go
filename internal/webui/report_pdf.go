package webui

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"netlens/internal/model"
)

// buildPDFReport intentionally uses only the standard library so the inspector
// remains easy to cross-compile. The generated PDF uses the PDF core Helvetica
// font and replaces unsupported control/non-Latin glyphs with '?'.
func buildPDFReport(flows []*model.Flow) []byte {
	lines := reportLines(flows)
	const perPage = 53
	pages := make([][]string, 0, (len(lines)+perPage-1)/perPage)
	for len(lines) > 0 {
		n := perPage
		if len(lines) < n {
			n = len(lines)
		}
		pages = append(pages, append([]string(nil), lines[:n]...))
		lines = lines[n:]
	}
	if len(pages) == 0 {
		pages = [][]string{{"NetLens Network Report"}}
	}

	// Objects: 1 catalog, 2 pages, 3 Helvetica font, then page/content pairs.
	objects := map[int][]byte{}
	objects[1] = []byte("<< /Type /Catalog /Pages 2 0 R >>")
	objects[3] = []byte("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	kids := make([]string, 0, len(pages))
	for i, pageLines := range pages {
		pageObj := 4 + i*2
		contentObj := pageObj + 1
		kids = append(kids, fmt.Sprintf("%d 0 R", pageObj))
		stream := pdfPageStream(pageLines, i+1, len(pages))
		objects[pageObj] = []byte(fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 842 595] /Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>", contentObj))
		objects[contentObj] = []byte(fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(stream), stream))
	}
	objects[2] = []byte(fmt.Sprintf("<< /Type /Pages /Count %d /Kids [%s] >>", len(pages), strings.Join(kids, " ")))
	maxObj := 3 + len(pages)*2

	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
	offsets := make([]int, maxObj+1)
	for i := 1; i <= maxObj; i++ {
		offsets[i] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i, objects[i])
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n", maxObj+1)
	out.WriteString("0000000000 65535 f \n")
	for i := 1; i <= maxObj; i++ {
		fmt.Fprintf(&out, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", maxObj+1, xref)
	return out.Bytes()
}

func pdfPageStream(lines []string, page, total int) string {
	var b strings.Builder
	b.WriteString("BT\n/F1 9 Tf\n38 558 Td\n")
	for i, line := range lines {
		if i == 0 {
			b.WriteString("/F1 15 Tf\n")
		}
		b.WriteString("(")
		b.WriteString(pdfEscape(line))
		b.WriteString(") Tj\n")
		if i == 0 {
			b.WriteString("/F1 9 Tf\n0 -20 Td\n")
		} else {
			b.WriteString("0 -10 Td\n")
		}
	}
	b.WriteString("ET\nBT /F1 8 Tf 730 20 Td (")
	b.WriteString(pdfEscape(fmt.Sprintf("Page %d / %d", page, total)))
	b.WriteString(") Tj ET")
	return b.String()
}

func pdfEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '(', ')', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n', '\r', '\t':
			b.WriteByte(' ')
		default:
			if r >= 32 && r <= 126 {
				b.WriteRune(r)
			} else {
				b.WriteByte('?')
			}
		}
	}
	return b.String()
}

func reportLines(flows []*model.Flow) []string {
	now := time.Now()
	var totalReq, totalRes, errors int
	var totalDuration int64
	hosts := map[string]int{}
	procs := map[string]int{}
	for _, f := range flows {
		totalReq += f.Request.Bytes
		totalRes += f.Response.Bytes
		totalDuration += f.DurationMS
		if f.Error != "" || f.Status >= 400 || f.Status == 0 {
			errors++
		}
		if f.Host != "" {
			hosts[f.Host]++
		}
		p := f.ProcessName
		if p == "" {
			p = "unknown"
		}
		procs[p]++
	}
	avg := int64(0)
	if len(flows) > 0 {
		avg = totalDuration / int64(len(flows))
	}
	lines := []string{
		"NetLens Network Report",
		"Generated: " + now.Format("2006-01-02 15:04:05"),
		fmt.Sprintf("Requests: %d    Errors: %d    Avg duration: %d ms    Request bytes: %s    Response bytes: %s", len(flows), errors, avg, humanBytes(totalReq), humanBytes(totalRes)),
		"",
		"Top hosts: " + topCounts(hosts, 6),
		"Top processes: " + topCounts(procs, 6),
		"",
		fmt.Sprintf("%-8s %-7s %-6s %-28s %-22s %-8s %-9s", "TIME", "METHOD", "STATUS", "HOST", "PROCESS", "MS", "BYTES"),
		strings.Repeat("-", 102),
	}
	for _, f := range flows {
		host := trimWidth(f.Host, 28)
		proc := trimWidth(f.ProcessName, 22)
		status := strconv.Itoa(f.Status)
		if f.Status == 0 {
			status = "ERR"
		}
		lines = append(lines, fmt.Sprintf("%-8s %-7s %-6s %-28s %-22s %8d %9s",
			f.StartedAt.Format("15:04:05"), trimWidth(f.Method, 7), status, host, proc, f.DurationMS, humanBytes(f.Request.Bytes+f.Response.Bytes)))
	}
	return lines
}

type countItem struct {
	key string
	n   int
}

func topCounts(m map[string]int, n int) string {
	items := make([]countItem, 0, len(m))
	for k, v := range m {
		items = append(items, countItem{k, v})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].n == items[j].n {
			return items[i].key < items[j].key
		}
		return items[i].n > items[j].n
	})
	if len(items) > n {
		items = items[:n]
	}
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, fmt.Sprintf("%s (%d)", trimWidth(it.key, 24), it.n))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

func trimWidth(s string, n int) string {
	if s == "" {
		return "-"
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 3 {
		return string(r[:n])
	}
	return string(r[:n-3]) + "..."
}

func humanBytes(n int) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	if n < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
}
