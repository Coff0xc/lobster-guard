package webui

import (
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/coff0xc/lobster-guard/pkg/utils"
)

// Run starts the Web GUI HTTP server and opens the browser.
func Run(target utils.Target, token string, useTLS bool, timeout time.Duration) error {
	state := NewAppState(target, token, useTLS, timeout)

	mux := http.NewServeMux()

	// Serve static files from Go constants (workaround for go:embed bug with [] in path)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/", "/index.html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(indexHTML))
		case "/app.css":
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
			w.Write([]byte(appCSS))
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
			w.Write([]byte(appJS))
		default:
			http.NotFound(w, r)
		}
	})

	// WebSocket
	mux.HandleFunc("/ws", handleWS(state))

	// API
	mux.HandleFunc("/api/scan", handleScan(state))
	mux.HandleFunc("/api/cancel", handleCancel(state))
	mux.HandleFunc("/api/export", handleExport(state))
	mux.HandleFunc("/api/status", handleStatus(state))

	// Find a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	addr := listener.Addr().String()
	url := fmt.Sprintf("http://%s", addr)

	fmt.Printf("\n🦞 LobsterGuard Web GUI\n")
	fmt.Printf("   地址: %s\n", url)
	fmt.Printf("   按 Ctrl+C 退出\n\n")

	// Auto-open browser
	go openBrowser(url)

	server := &http.Server{
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}
	return server.Serve(listener)
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Run()
}
