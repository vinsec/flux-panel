package panel

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type nodeRelease struct {
	directory, manifestSHA, installerSHA string
	files                                map[string]bool
}

func loadNodeRelease(directory string) (*nodeRelease, error) {
	if directory == "" {
		return nil, fmt.Errorf("node package not bundled")
	}
	manifest, err := os.ReadFile(filepath.Join(directory, "SHA256SUMS"))
	if err != nil || len(manifest) > 65536 || len(manifest) == 0 {
		return nil, fmt.Errorf("node package manifest unavailable")
	}
	r := &nodeRelease{directory: directory, files: map[string]bool{"SHA256SUMS": true}}
	sum := sha256.Sum256(manifest)
	r.manifestSHA = hex.EncodeToString(sum[:])
	for _, line := range strings.Split(strings.TrimSpace(string(manifest)), "\n") {
		parts := strings.Fields(line)
		if len(parts) != 2 || !hashPattern.MatchString(parts[0]) || !nodeReleaseAssetName(parts[1]) || r.files[parts[1]] {
			return nil, fmt.Errorf("invalid node package manifest")
		}
		name := parts[1]
		p := filepath.Join(directory, name)
		stat, e := os.Lstat(p)
		if e != nil || !stat.Mode().IsRegular() {
			return nil, fmt.Errorf("invalid node package file")
		}
		f, e := os.Open(p)
		if e != nil {
			return nil, e
		}
		h := sha256.New()
		_, e = io.Copy(h, f)
		f.Close()
		if e != nil || hex.EncodeToString(h.Sum(nil)) != strings.ToLower(parts[0]) {
			return nil, fmt.Errorf("node package checksum mismatch")
		}
		r.files[name] = true
		if name == "install.sh" {
			r.installerSHA = strings.ToLower(parts[0])
		}
	}
	for _, name := range []string{"install.sh", "flux-agent-linux-amd64", "flux-agent-linux-arm64", "gost-managed-linux-amd64", "gost-managed-linux-arm64", "flux-agent.service", "flux-kernel.service", "flux-agent-tmpfiles.conf"} {
		if !r.files[name] {
			return nil, fmt.Errorf("incomplete bundled node package")
		}
	}
	return r, nil
}

func nodeReleaseAssetName(name string) bool {
	switch name {
	case "install.sh", "SHA256SUMS", "release.json", "gost-wss-evidence.json", "flux-agent.service", "flux-kernel.service", "flux-agent-tmpfiles.conf", "flux-kernel-local-shaping.conf", "flux-local-shaping-prepare.service", "flux-agent-linux-amd64", "flux-agent-linux-arm64", "gost-managed-linux-amd64", "gost-managed-linux-arm64", "gost-linux-amd64", "gost-linux-arm64":
		return true
	}
	return false
}

// Public downloads contain programs only; credentials stay in the authenticated
// install response and are never stored alongside these assets.
func (p *Panel) serveNodeRelease(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "HEAD" {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", 405)
		return
	}
	pack := p.nodeRelease
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/node-install/"), "/")
	if pack == nil || len(parts) != 2 || parts[0] != pack.manifestSHA || !nodeReleaseAssetName(parts[1]) || !pack.files[parts[1]] {
		http.NotFound(w, r)
		return
	}
	entry, err := os.Lstat(filepath.Join(pack.directory, parts[1]))
	if err != nil || !entry.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(filepath.Join(pack.directory, parts[1]))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, parts[1], stat.ModTime(), f)
}
