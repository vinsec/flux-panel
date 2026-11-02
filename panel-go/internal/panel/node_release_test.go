package panel

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func testNodeRelease(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	names := []string{"install.sh", "flux-agent-linux-amd64", "flux-agent-linux-arm64", "gost-managed-linux-amd64", "gost-managed-linux-arm64", "gost-linux-amd64", "gost-linux-arm64", "gost-wss-evidence.json", "flux-agent.service", "flux-kernel.service", "flux-agent-tmpfiles.conf"}
	sort.Strings(names)
	var sums strings.Builder
	for _, name := range names {
		content := []byte("fixture-program:" + name)
		if name == "install.sh" {
			content = []byte("#!/bin/sh\nprintf 'isolated installation command verified\\n'\n")
		}
		if err := os.WriteFile(filepath.Join(dir, name), content, 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(content)
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(sum[:]), name)
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums.String()), 0600); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "private-node-config.json"), []byte("must-not-be-public"), 0600)
	return dir
}

func TestBundledNodeDownloadsArePinnedAndExcludeCredentials(t *testing.T) {
	dir := testNodeRelease(t)
	p := New(nil, Config{JWTSecret: "test-only", NodeReleaseDir: dir})
	if p.nodeRelease == nil {
		t.Fatal("package failed to load")
	}
	server := httptest.NewServer(p.Handler())
	defer server.Close()
	base := server.URL + "/node-install/" + p.nodeRelease.manifestSHA + "/"
	response, err := http.Get(base + "install.sh")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || !strings.Contains(string(body), "isolated installation") || !strings.Contains(response.Header.Get("Cache-Control"), "immutable") {
		t.Fatal(response.Status, string(body))
	}
	for _, suffix := range []string{"private-node-config.json", "config.json", "../private-node-config.json", "%2e%2e%2fprivate-node-config.json", "..%2f..%2f.env", ""} {
		r, err := http.Get(base + suffix)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != 404 || strings.Contains(string(b), "must-not-be-public") {
			t.Fatal("unexpected download", suffix, r.StatusCode)
		}
	}
	r, err := http.Head(base + "flux-agent-linux-amd64")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 200 || r.ContentLength <= 0 {
		t.Fatal(r.Status)
	}
	r, err = http.Post(base+"install.sh", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 405 {
		t.Fatal(r.Status)
	}
	r, err = http.Get(server.URL + "/node-install/" + strings.Repeat("0", 64) + "/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 404 {
		t.Fatal(r.Status)
	}
}

func TestCorruptOrLinkedNodePackageCannotBecomeInstallSource(t *testing.T) {
	for _, linked := range []bool{false, true} {
		dir := testNodeRelease(t)
		file := filepath.Join(dir, "install.sh")
		if linked {
			os.Remove(file)
			os.Symlink(filepath.Join(dir, "private-node-config.json"), file)
		} else {
			os.WriteFile(file, []byte("modified installer"), 0600)
		}
		if _, err := loadNodeRelease(dir); err == nil {
			t.Fatal("invalid installer accepted", linked)
		}
	}
}

func TestDefaultInstallCommandNeedsNoExternalReleaseConfiguration(t *testing.T) {
	f := setupDB(t)
	node := f.seedNode("kernel")
	dir := testNodeRelease(t)
	pack, err := loadNodeRelease(dir)
	if err != nil {
		t.Fatal(err)
	}
	f.p.nodeRelease = pack
	f.p.setConfig(f.store(), "ip", "wss://panel.example.test")
	for _, engine := range []string{"kernel", "gost"} {
		f.store().update("node", node, M{"engine": engine})
		r := f.post(t, "/api/v1/node/install", M{"id": node})
		if num(r["code"]) != 0 {
			t.Fatal(r)
		}
		command := str(r["data"])
		if !strings.Contains(command, "https://panel.example.test/node-install/"+pack.manifestSHA+"/install.sh") || !strings.Contains(command, pack.installerSHA) || !strings.Contains(command, "--engine "+engine) || !strings.Contains(command, "sha256sum --strict -c") {
			t.Fatal("invalid pinned install command")
		}
		if engine == "kernel" && !strings.Contains(command, "--install-deps") {
			t.Fatal("fresh nodes need dependency installation")
		}
	}
}
