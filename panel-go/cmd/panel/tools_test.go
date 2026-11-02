package main

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

func TestHealthcheckCommand(t *testing.T) {
	var healthy atomic.Bool
	healthy.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Error(r.URL.Path)
		}
		if !healthy.Load() {
			w.WriteHeader(503)
		}
	}))
	defer server.Close()
	t.Setenv("PANEL_LISTEN", strings.TrimPrefix(server.URL, "http://"))
	if err := runTool([]string{"healthcheck"}); err != nil {
		t.Fatal(err)
	}
	healthy.Store(false)
	if err := runTool([]string{"healthcheck"}); err == nil {
		t.Fatal("unhealthy service accepted")
	}
	server.Close()
	if err := runTool([]string{"healthcheck"}); err == nil {
		t.Fatal("stopped service accepted")
	}
	if err := runTool([]string{"unknown"}); err == nil {
		t.Fatal("unknown command accepted")
	}
}

func TestExplicitMigrationPreservesExistingLedger(t *testing.T) {
	dsn := os.Getenv("FLUX_TEST_DSN")
	if dsn == "" {
		t.Skip("requires disposable local MySQL")
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cfg.DBName, "flux_go_test") {
		t.Fatal("only disposable flux_go_test databases are allowed")
	}
	// Separate schema: this command test never shares the panel test package's destructive fixture.
	cfg.DBName += "_migrate"
	cfg.MultiStatements = true
	admin := *cfg
	admin.DBName = ""
	db, err := sql.Open("mysql", admin.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	name := "`" + strings.ReplaceAll(cfg.DBName, "`", "``") + "`"
	if _, err = db.Exec("DROP DATABASE IF EXISTS " + name); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("CREATE DATABASE " + name + " CHARACTER SET utf8mb4"); err != nil {
		t.Fatal(err)
	}
	defer db.Exec("DROP DATABASE " + name)
	schema, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer schema.Close()
	root := os.Getenv("FLUX_TEST_SCHEMA_ROOT")
	if root == "" {
		root = "../../.."
	}
	root, err = filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = os.Symlink(filepath.Join(root, "gost.sql"), filepath.Join(dir, "gost.sql")); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Join(root, "database/migrations"), filepath.Join(dir, "migrations")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err = migrateDatabase(ctx, schema, dir, true); err != nil {
		t.Fatal(err)
	}
	if _, err = schema.Exec("UPDATE user SET in_flow=123456,out_flow=654321 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if err = migrateDatabase(ctx, schema, dir, true); err == nil {
		t.Fatal("reinitialization of existing database accepted")
	}
	for i := 0; i < 2; i++ {
		if err = migrateDatabase(ctx, schema, dir, false); err != nil {
			t.Fatal(err)
		}
	}
	var up, down int64
	if err = schema.QueryRow("SELECT in_flow,out_flow FROM user WHERE id=1").Scan(&up, &down); err != nil || up != 123456 || down != 654321 {
		t.Fatal("migration changed ledger", up, down, err)
	}
	if err = migrateDatabase(ctx, schema, t.TempDir(), false); err == nil {
		t.Fatal("incomplete bundle accepted")
	}
}
