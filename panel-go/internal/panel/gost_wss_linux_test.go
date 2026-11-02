package panel

import (
	"encoding/pem"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestUnchangedGostWSSControlAndActualTCPUDP(t *testing.T) {
	binary := os.Getenv("FLUX_TEST_GOST_BIN")
	if binary == "" {
		t.Skip("run with the frozen Linux GOST binary in the isolated verifier")
	}
	f := setupDB(t)
	secure := httptest.NewTLSServer(f.p.Handler())
	defer secure.Close()
	node := f.seedNode("gost")
	n := f.store().get("node", node)
	f.store().update("node", node, M{"status": 0})
	dir := t.TempDir()
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: secure.Certificate().Raw})
	certPath := filepath.Join(dir, "test-ca.pem")
	must(os.WriteFile(certPath, cert, 0600))
	must(os.WriteFile(filepath.Join(dir, "config.json"), []byte(jsonText(M{"addr": "wss" + secure.URL[5:], "secret": n["secret"]})), 0600))
	must(os.WriteFile(filepath.Join(dir, "gost.json"), []byte("{}"), 0600))
	logFile, e := os.Create(filepath.Join(dir, "gost.log"))
	if e != nil {
		t.Fatal(e)
	}
	defer logFile.Close()
	cmd := exec.Command(binary)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+certPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	target, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	targetPort := target.Addr().(*net.TCPAddr).Port
	udp, e := net.ListenPacket("udp", target.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	go func() {
		for {
			c, e := target.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	go func() {
		b := make([]byte, 2048)
		for {
			n, addr, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			udp.WriteTo(b[:n], addr)
		}
	}()
	entry, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := entry.Addr().(*net.TCPAddr).Port
	entry.Close()
	f.store().update("node", node, M{"portSta": port, "portEnd": port, "ip": "127.0.0.1", "serverIp": "127.0.0.1"})
	deadline := time.Now().Add(15 * time.Second)
	for num(f.store().get("node", node)["status"]) != 1 {
		if time.Now().After(deadline) {
			b, _ := os.ReadFile(filepath.Join(dir, "gost.log"))
			t.Fatalf("frozen GOST did not authenticate over WSS: %s", b)
		}
		time.Sleep(50 * time.Millisecond)
	}
	tunnel := f.seedTunnel(node, "gost")
	f.post(t, "/api/v1/forward/create", M{"name": "wss-real-gost", "tunnelId": tunnel, "inPort": port, "remoteAddr": join("127.0.0.1", targetPort)})
	for _, network := range []string{"tcp", "udp"} {
		c, e := net.DialTimeout(network, join("127.0.0.1", port), time.Second)
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		payload := []byte("isolated-wss-echo")
		if _, e = c.Write(payload); e != nil {
			t.Fatal(e)
		}
		b := make([]byte, len(payload))
		if _, e = io.ReadFull(c, b); e != nil {
			t.Fatal(network, e)
		}
		c.Close()
		if string(b) != string(payload) {
			t.Fatal("payload changed")
		}
	}
	fwd := f.store().one("SELECT id FROM forward WHERE name='wss-real-gost'")
	reportDeadline := time.Now().Add(15 * time.Second)
	for {
		row := f.store().get("forward", fwd["id"])
		if num(row["inFlow"])+num(row["outFlow"]) > 0 {
			break
		}
		if time.Now().After(reportDeadline) {
			t.Fatal("trusted WSS GOST did not report actual traffic over HTTPS")
		}
		time.Sleep(50 * time.Millisecond)
	}

	f.post(t, "/api/v1/forward/delete", M{"id": fwd["id"]})
	t.Log("unchanged frozen GOST: trusted WSS control, encrypted commands, actual TCP+UDP, deletion")
}
