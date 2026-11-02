package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Tools are explicit commands. Normal server startup never executes DDL.
func runTool(args []string) error {
	switch args[0] {
	case "healthcheck":
		if len(args) != 1 {
			return errors.New("usage: flux-panel healthcheck")
		}
		addr := os.Getenv("PANEL_LISTEN")
		if addr == "" {
			addr = "127.0.0.1:6365"
		}
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return err
		}
		switch host {
		case "", "0.0.0.0":
			host = "127.0.0.1"
		case "::":
			host = "::1"
		}
		client := http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{Proxy: nil}}
		response, err := client.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
		if err != nil {
			return errors.New("panel healthcheck failed")
		}
		defer response.Body.Close()
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("panel healthcheck status %d", response.StatusCode)
		}
		return nil
	case "migrate":
		flags := flag.NewFlagSet("migrate", flag.ContinueOnError)
		dir := os.Getenv("PANEL_SCHEMA_DIR")
		if dir == "" {
			dir = "."
		}
		flags.StringVar(&dir, "dir", dir, "directory containing gost.sql and migrations/")
		initialize := flags.Bool("init", false, "initialize an empty database before applying migrations")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected migration arguments")
		}
		cfg := mysql.NewConfig()
		cfg.User = os.Getenv("DB_USER")
		cfg.Passwd = os.Getenv("DB_PASSWORD")
		cfg.Net = "tcp"
		cfg.DBName = os.Getenv("DB_NAME")
		cfg.MultiStatements = true
		cfg.Timeout = 10 * time.Second
		host := os.Getenv("DB_HOST")
		if host == "" {
			host = "127.0.0.1:3306"
		}
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(strings.Trim(host, "[]"), "3306")
		}
		cfg.Addr = host
		db, err := sql.Open("mysql", cfg.FormatDSN())
		if err != nil {
			return err
		}
		defer db.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		return migrateDatabase(ctx, db, dir, *initialize)
	default:
		return errors.New("usage: flux-panel [healthcheck | migrate [--init] [--dir PATH]]")
	}
}

var forwardMigrations = []string{"001-forward-engines.sql", "002-engine-foundation.sql", "003-engine-p1.sql", "004-node-kernel-backend.sql", "005-native-only.sql", "006-go-panel-runtime.sql", "007-managed-agent.sql"}

func migrateDatabase(ctx context.Context, db *sql.DB, dir string, initialize bool) error {
	// Read the entire bundle before changing any data, so incomplete packages fail first.
	files := append([]string{}, forwardMigrations...)
	if initialize {
		files = append([]string{"gost.sql"}, files...)
	}
	bodies := make([][]byte, len(files))
	for i, name := range files {
		p := filepath.Join(dir, "migrations", name)
		if name == "gost.sql" {
			p = filepath.Join(dir, name)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("missing schema file %s: %w", name, err)
		}
		bodies[i] = b
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	var locked int
	if err = conn.QueryRowContext(ctx, "SELECT GET_LOCK('flux-panel-schema-migrate',0)").Scan(&locked); err != nil {
		return err
	}
	if locked != 1 {
		return errors.New("another migration is running")
	}
	defer func() {
		release, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := conn.ExecContext(release, "DO RELEASE_LOCK('flux-panel-schema-migrate')")
		if err != nil {
			conn.Raw(func(any) error { return driver.ErrBadConn })
		}
	}()
	if initialize {
		var count int
		if err = conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()").Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return errors.New("--init requires an empty database; use migrate without --init for an existing schema")
		}
	}
	for i, body := range bodies {
		if _, err = conn.ExecContext(ctx, string(body)); err != nil {
			return fmt.Errorf("migration %s failed: %w", files[i], err)
		}
		fmt.Fprintln(os.Stdout, "Applied", files[i])
	}
	return nil
}
