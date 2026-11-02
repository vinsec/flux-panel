package main

import (
	"context"
	"database/sql"
	"github.com/go-sql-driver/mysql"
	"github.com/vinsec/flux-panel/panel-go/internal/panel"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata"
)

func main() {
	if len(os.Args) > 1 {
		if err := runTool(os.Args[1:]); err != nil {
			slog.Error("panel command failed", "error", err)
			os.Exit(1)
		}
		return
	}
	cfg := mysql.NewConfig()
	cfg.User = os.Getenv("DB_USER")
	cfg.Passwd = os.Getenv("DB_PASSWORD")
	cfg.Net = "tcp"
	host := os.Getenv("DB_HOST")
	if host == "" {
		host = "127.0.0.1:3306"
	}
	if _, _, e := net.SplitHostPort(host); e != nil {
		host = net.JoinHostPort(strings.Trim(host, "[]"), "3306")
	}
	cfg.Addr = host
	cfg.DBName = os.Getenv("DB_NAME")
	cfg.Collation = "utf8mb4_general_ci"
	cfg.Timeout = 10 * time.Second
	cfg.ReadTimeout = 30 * time.Second
	cfg.WriteTimeout = 30 * time.Second
	db, e := sql.Open("mysql", cfg.FormatDSN())
	if e != nil {
		slog.Error("database configuration failed")
		os.Exit(1)
	}
	defer db.Close()
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(500 * time.Second)
	sessionMillis := numberEnv("ENGINE_AUTH_SESSION_MILLIS", 900000)
	leaseMax := numberEnv("ENGINE_LEASE_MAX_BYTES", 1<<32)
	leaseDuration := numberEnv("ENGINE_LEASE_DURATION_MILLIS", 30000)
	sessionMillis = max(60000, min(3600000, sessionMillis))
	if leaseMax < 128 || leaseMax > 1<<32 || leaseDuration < 1000 || leaseDuration > 60000 {
		panic("invalid credit lease configuration")
	}
	p := panel.New(db, panel.Config{JWTSecret: os.Getenv("JWT_SECRET"), SessionMillis: sessionMillis, LeaseMaxBytes: leaseMax, LeaseDurationMillis: leaseDuration, NodeReleaseDir: os.Getenv("NODE_RELEASE_DIR"), ReleaseBase: os.Getenv("NODE_RELEASE_BASE_URL"), ManifestSHA: os.Getenv("NODE_RELEASE_MANIFEST_SHA256"), InstallerSHA: os.Getenv("NODE_RELEASE_INSTALLER_SHA256"), AllowLegacyQuery: os.Getenv("ENGINE_AUTH_ALLOW_LEGACY_QUERY") != "false", ReadOnly: os.Getenv("PANEL_READ_ONLY") == "true", TimeZone: os.Getenv("TZ")})
	addr := os.Getenv("PANEL_LISTEN")
	if addr == "" {
		addr = "127.0.0.1:6365"
	}
	srv := &http.Server{Addr: addr, Handler: p.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 20}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	p.Start(ctx)
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		shutdown, c := context.WithTimeout(context.Background(), 30*time.Second)
		defer c()
		srv.Shutdown(shutdown)
		p.Close()
	}()
	slog.Info("panel listening", "address", addr)
	if e := srv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
		slog.Error("HTTP server failed")
		cancel()
		p.Close()
		<-shutdownDone
		os.Exit(1)
	}
	<-shutdownDone
}

func numberEnv(name string, defaultValue int64) int64 {
	v := os.Getenv(name)
	if v == "" {
		return defaultValue
	}
	n, e := strconv.ParseInt(v, 10, 64)
	if e != nil {
		panic("invalid numeric configuration: " + name)
	}
	return n
}
