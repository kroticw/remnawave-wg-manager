// Command remnawave-wg-manager serves the WireGuard client management page,
// REST API and MCP endpoint next to a Remnawave panel.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kroticw/remnawave-wg-manager/internal/clients"
	"github.com/kroticw/remnawave-wg-manager/internal/httpapi"
	"github.com/kroticw/remnawave-wg-manager/internal/mcpserver"
	"github.com/kroticw/remnawave-wg-manager/internal/panel"
	"github.com/kroticw/remnawave-wg-manager/internal/web"
)

type config struct {
	PanelURL     string
	BasePath     string
	LoginPath    string
	Listen       string
	EndpointHost string
	DNS          string
	MTU          int
	SubnetPrefix int
	Forwarded    bool
}

func or(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func intIn(getenv func(string) string, key string, def, lo, hi int) (int, error) {
	raw := getenv(key)
	if raw == "" {
		return def, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < lo || v > hi {
		return 0, fmt.Errorf("%s must be an integer in [%d, %d], got %q", key, lo, hi, raw)
	}
	return v, nil
}

func loadConfig(getenv func(string) string) (config, error) {
	c := config{
		PanelURL:     strings.TrimSuffix(getenv("PANEL_URL"), "/"),
		BasePath:     "/" + strings.Trim(or(getenv("BASE_PATH"), "/wg"), "/"),
		LoginPath:    or(getenv("LOGIN_PATH"), "/auth/login"),
		Listen:       or(getenv("LISTEN"), ":8080"),
		EndpointHost: getenv("ENDPOINT_HOST"),
		DNS:          or(getenv("CLIENT_DNS"), "1.1.1.1, 8.8.8.8"),
		Forwarded:    getenv("FORWARDED_HEADERS") != "false",
	}
	if c.PanelURL == "" {
		return c, errors.New("PANEL_URL is required")
	}
	var err error
	if c.MTU, err = intIn(getenv, "CLIENT_MTU", 1380, 1280, 1500); err != nil {
		return c, err
	}
	if c.SubnetPrefix, err = intIn(getenv, "SUBNET_PREFIX", 24, 16, 30); err != nil {
		return c, err
	}
	return c, nil
}

func healthcheck(listen string) int {
	port := listen[strings.LastIndex(listen, ":")+1:]
	base := "/" + strings.Trim(or(os.Getenv("BASE_PATH"), "/wg"), "/")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Always loopback; only the port and path come from our own environment.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+port+base+"/healthz", nil) //nolint:gosec // G704: loopback only
	if err != nil {
		return 1
	}
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G704: loopback only
	if err != nil {
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck(or(os.Getenv("LISTEN"), ":8080")))
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(2)
	}
	pc := &panel.Client{BaseURL: cfg.PanelURL, HTTP: &http.Client{Timeout: 30 * time.Second}, Forwarded: cfg.Forwarded}
	mgr := &clients.Manager{Panel: pc, SubnetPrefix: cfg.SubnetPrefix, EndpointHost: cfg.EndpointHost, DNS: cfg.DNS, MTU: cfg.MTU}

	mux := http.NewServeMux()
	mux.Handle(cfg.BasePath+"/mcp", httpapi.SecurityHeaders(mcpserver.Handler(mgr)))
	mux.Handle("/", httpapi.New(mgr, cfg.BasePath, cfg.LoginPath, web.Static))

	srv := &http.Server{Addr: cfg.Listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Info("listening", "addr", cfg.Listen, "base", cfg.BasePath, "panel", cfg.PanelURL)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}
