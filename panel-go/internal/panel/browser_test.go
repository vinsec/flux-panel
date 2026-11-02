package panel

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestBrowserFrontendFlows(t *testing.T) {
	script := os.Getenv("FLUX_TEST_BROWSER_SCRIPT")
	if script == "" {
		t.Skip("browser workflow is run explicitly with the local cached browser runtime")
	}
	oracle := filepath.Join(t.TempDir(), "challenge-oracle.json")
	t.Setenv("FLUX_TEST_BROWSER_ORACLE", oracle)
	t.Setenv("FLUX_TEST_BROWSER_LISTEN", "127.0.0.1:16365")
	f := setupDB(t)
	f.store().update("user", 1, M{"user": "browser_用户~?", "pwd": passwordHash("browser-password")})
	cmd := exec.Command("node", script)
	cmd.Env = append(os.Environ(), "FLUX_BROWSER_BACKEND="+f.http.URL, "FLUX_BROWSER_ORACLE="+oracle)
	output, e := cmd.CombinedOutput()
	t.Log(string(output))
	if e != nil {
		t.Fatal(e)
	}
}
