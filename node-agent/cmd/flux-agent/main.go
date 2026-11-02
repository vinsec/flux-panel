package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/vinsec/flux-panel/node-agent/internal/control"
	"github.com/vinsec/flux-panel/node-agent/internal/engine"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	config := flag.String("config", "config.json", "configuration file")
	helperMode := flag.Bool("kernel-helper", false, "serve allowlisted local kernel operations")
	helperUser := flag.String("helper-user", "flux-agent", "allowed local network-process account or numeric UID")
	standalone := flag.Bool("standalone", false, "explicit legacy in-process kernel mode")
	serviceConfig := flag.String("write-service-config", "", "write a protected service config with local helper enabled")
	previousConfig := flag.String("same-node-config", "", "require matching node identity in this previous config")
	maintenance := flag.String("maintenance", "", "pause/settle and backup, migrate, rollback, uninstall, or settle")
	printBackup := flag.Bool("print-backup-path", false, "print only the completed maintenance backup path")
	backup := flag.String("backup-dir", "", "new backup directory (existing source for rollback)")
	offline := flag.Bool("offline", false, "retain a fail-closed guard until panel settlement")
	checkGostConfig := flag.Bool("check-gost-config", false, "validate a GOST panel URL without touching service state")
	expectedState := flag.String("expected-state-path", "", "required state path for a packaged installation")
	ready := flag.Bool("ready", false, "require a fresh authenticated control/report receipt")
	checkConfig := flag.Bool("check-config", false, "validate config without printing credentials or touching rules")
	preflight := flag.Bool("preflight", false, "probe kernel compatibility without managing forwarding")
	status := flag.Bool("status", false, "read checkpoint metadata without changing rules")
	testFault := flag.String("test-fault", "", "crash injection in a marked disposable test container")
	plan := flag.String("plan", "", "render a single ForwardSpec without executing commands")
	prepareLocal := flag.Bool("prepare-local-shaping", false, "short-lived administrative preparation of the embedded local BPF program")
	managedOutput := flag.String("write-managed-config", "", "write config with a pinned managed GOST binary")
	managedBinary := flag.String("managed-binary", "", "installed managed GOST executable")
	managedSHA := flag.String("managed-sha256", "", "pinned managed GOST SHA256")
	flag.Parse()
	if *prepareLocal {
		result, e := engine.PrepareLocalShaping()
		if e != nil {
			log.Fatal(e)
		}
		b, _ := json.Marshal(result)
		fmt.Println(string(b))
		return
	}
	if *plan != "" {
		b, e := os.ReadFile(*plan)
		if e != nil {
			log.Fatal(e)
		}
		var s engine.Spec
		if e = json.Unmarshal(b, &s); e != nil {
			log.Fatal(e)
		}
		if s, e = s.Normalize(); e != nil {
			log.Fatal(e)
		}
		out := engine.Render(map[string]engine.Spec{s.ID: s}, nil)

		b, _ = json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return
	}
	b, e := os.ReadFile(*config)
	if e != nil && !(*preflight && os.IsNotExist(e)) {
		log.Fatal(e)
	}
	var c control.Config
	if len(b) > 0 {
		if e = json.Unmarshal(b, &c); e != nil {
			log.Fatal(e)
		}
	}
	if *managedOutput != "" {
		if !filepath.IsAbs(*managedOutput) || !filepath.IsAbs(*managedBinary) || len(*managedSHA) != 64 {
			log.Fatal("invalid managed config output")
		}
		if value, err := hex.DecodeString(*managedSHA); err != nil || len(value) != 32 {
			log.Fatal("invalid managed binary hash")
		}
		c.ManagedGost = &control.ManagedGostConfig{Binary: *managedBinary, SHA256: *managedSHA, Socket: "/run/flux-agent-gost/control.sock"}
		data, e := json.Marshal(c)
		if e != nil {
			log.Fatal(e)
		}
		if e = os.WriteFile(*managedOutput, data, 0600); e != nil {
			log.Fatal(e)
		}
		return
	}
	if c.Iptables != "" {
		log.Fatal("iptables configuration is retired; only native nftables is supported")
	}
	if c.KernelBackend != "" && c.KernelBackend != "nftables" {
		log.Fatal("iptables/unknown backend is retired; only native nftables is supported")
	}
	c.KernelBackend = "nftables"
	if *preflight {
		k := engine.NativeKernel{}
		k.EnableNative(c.StatePath)
		report, e := k.Preflight()
		b, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(b))
		if e != nil {
			log.Fatal(e)
		}
		return
	}
	if *standalone {
		c.HelperSocket = ""
	}
	if (*status || *ready) && c.HelperSocket != "" {
		info := (&control.RemoteManager{Socket: c.HelperSocket}).Info()
		if *ready {
			connected, _ := info["lastConnectedAt"].(float64)
			ack, _ := info["lastAckAt"].(float64)
			blocked, _ := info["blocked"].(bool)
			if blocked || connected == 0 || ack == 0 || time.Now().UnixMilli()-int64(ack) > 30000 {
				os.Exit(1)
			}
			fmt.Println("ready")
			return
		}
		b, _ = json.MarshalIndent(info, "", "  ")
		fmt.Println(string(b))
		return
	}
	if *status || *ready {
		data, e := os.ReadFile(c.StatePath)
		if e != nil {
			log.Fatal(e)
		}
		var state engine.State
		if e = json.Unmarshal(data, &state); e != nil {
			log.Fatal(e)
		}
		if *ready {
			if state.MaintenancePending || state.AccountingBlocked || state.LastConnectedAt == 0 || state.LastAckAt == 0 || time.Now().UnixMilli()-state.LastAckAt > 30000 {
				os.Exit(1)
			}
			fmt.Println("ready")
			return
		}
		b, _ := json.MarshalIndent(map[string]interface{}{"lastAckAt": state.LastAckAt, "connectedAt": state.LastConnectedAt, "maintenancePending": state.MaintenancePending, "epoch": state.Epoch, "generation": state.Generation, "stateVersion": state.FormatVersion, "lastDurableAt": state.LastDurableAt, "forwards": len(state.Rules), "freeTokens": len(state.FreeTokens), "recovery": state.Recovery}, "", "  ")
		fmt.Println(string(b))
		return
	}
	if *checkGostConfig {
		if c.Secret == "" {
			log.Fatal("secret required")
		}
		if _, _, e = c.URLs(); e != nil {
			log.Fatal(e)
		}
		fmt.Println("{\"valid\":true}")
		return
	}
	if c.Secret == "" || !c.Apply || c.StatePath == "" {
		log.Fatal("secret, statePath and explicit apply=true are required")
	}
	if *checkConfig {
		if !filepath.IsAbs(c.StatePath) || *expectedState != "" && c.StatePath != *expectedState {
			log.Fatal("state path must match the packaged state directory")
		}
		if _, _, e = c.URLs(); e != nil {
			log.Fatal(e)
		}
		fmt.Println("{\"valid\":true}")
		return
	}
	if *previousConfig != "" {
		old, e := os.ReadFile(*previousConfig)
		if e != nil {
			log.Fatal(e)
		}
		var prior control.Config
		if e = json.Unmarshal(old, &prior); e != nil {
			log.Fatal(e)
		}
		if strings.TrimRight(prior.Addr, "/") != strings.TrimRight(c.Addr, "/") || prior.Secret != c.Secret || prior.StatePath != c.StatePath {
			log.Fatal("node identity or ledger path differs")
		}
		oldBackend, newBackend := prior.KernelBackend, c.KernelBackend
		if oldBackend == "" {
			oldBackend = "iptables"
		}
		if newBackend == "" {
			newBackend = "nftables"
		}
		if oldBackend != newBackend {
			log.Fatal("kernel backend differs; complete explicit settled migration before installation")
		}
		fmt.Println("same node identity")
		return
	}
	if *serviceConfig != "" {
		if !filepath.IsAbs(*serviceConfig) {
			log.Fatal("service config output must be absolute")
		}
		c.HelperSocket = "/run/flux-agent/kernel.sock"
		body, e := json.Marshal(c)
		if e != nil {
			log.Fatal(e)
		}
		if e = os.WriteFile(*serviceConfig, body, 0600); e != nil {
			log.Fatal(e)
		}
		return
	}
	if c.HelperSocket != "" && !*helperMode && *maintenance == "" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		finish, e := control.StartManagedGost(ctx, c)
		if e != nil {
			log.Fatal(e)
		}
		defer finish()
		remote := &control.RemoteManager{Socket: c.HelperSocket}
		deadline := time.Now().Add(30 * time.Second)
		for {
			if info := remote.Info(); info["epoch"] != nil {
				break
			}
			if time.Now().After(deadline) {
				log.Fatal("kernel helper readiness timed out")
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(200 * time.Millisecond):
			}
		}
		if e = control.Run(ctx, c, remote); e != nil {
			log.Fatal(e)
		}
		return
	}
	if e = os.MkdirAll(filepath.Dir(c.StatePath), 0700); e != nil {
		log.Fatal(e)
	}
	lock, e := os.OpenFile(c.StatePath+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		log.Fatal(e)
	}
	defer lock.Close()
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		log.Fatal("another agent owns this state directory")
	}
	if _, _, e = c.URLs(); e != nil {
		log.Fatal(e)
	}
	if e = engine.ValidateCheckpointBackend(c.StatePath); e != nil {
		log.Fatal(e)
	}
	namespace, e := engine.AcquireNamespaceLock()
	if e != nil {
		log.Fatal(e)
	}
	defer namespace.Close()
	k := engine.NativeKernel{}
	k.EnableNative(c.StatePath)
	k.Mode = "kernel"
	if c.ManagedGost != nil {
		var err error
		k.Gost, err = engine.NewGostRunner(c.ManagedGost.Socket, c.StatePath)
		if err != nil {
			log.Fatal(err)
		}
		if c.ForwardingMode != "" {
			k.Mode = c.ForwardingMode
		}
		if data, err := os.ReadFile(c.StatePath); err == nil {
			var s engine.State
			if err = json.Unmarshal(data, &s); err != nil {
				log.Fatal(err)
			}
			if s.ForwardingMode != "" {
				k.Mode = s.ForwardingMode
			}
			if s.EngineSwitch.Status == "running" || s.EngineSwitch.Status == "queued" {
				k.Mode = s.EngineSwitch.From
			}
		}
		if k.Mode != "kernel" && k.Mode != "gost" {
			log.Fatal("invalid forwardingMode")
		}
	}
	if c.HelperSocket == "" && c.ManagedGost != nil {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		finish, err := control.StartManagedGost(ctx, c)
		if err != nil {
			log.Fatal(err)
		}
		defer finish()
		time.Sleep(300 * time.Millisecond)
	}
	if *testFault != "" {
		if !c.AllowInsecure {
			log.Fatal("fault injection is disabled outside isolated tests")
		}
		if _, e = os.Stat("/run/flux-test-disposable"); e != nil {
			log.Fatal("fault injection requires the disposable marker")
		}
		engine.MaintenanceFault = func(stage string) {
			if *testFault == "maintenance:"+stage {
				os.Exit(82)
			}
		}
	}
	if *maintenance == "resume" {
		data, err := os.ReadFile(c.StatePath + ".maintenance")
		if err != nil {
			log.Fatal(err)
		}
		var intent struct {
			Action string `json:"action"`
			Backup string `json:"backup"`
		}
		if err = json.Unmarshal(data, &intent); err != nil {
			log.Fatal(err)
		}
		*maintenance = intent.Action
		*backup = intent.Backup
	}
	if *maintenance != "" {
		if *maintenance == "migrate" {
			if _, e = k.Preflight(); e != nil {
				log.Fatal(e)
			}
		}
		result, e := engine.Maintain(c.StatePath, *config, *maintenance, *backup, &k, *offline, func(r engine.Report) (engine.Acknowledgement, error) { return control.SettleMaintenance(c, r) })
		if e != nil {
			log.Fatal(e)
		}
		if *printBackup {
			fmt.Println(result.Backup)
			return
		}
		b, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(b))
		return
	}
	if _, e = os.Stat(c.StatePath + ".maintenance"); e == nil {
		_ = k.Quiesce()
		log.Fatal("pending maintenance intent; repeat its action and backup directory before starting")
	}
	if e = k.Initialize(); e != nil {
		log.Fatal(e)
	}
	if *helperMode && k.Gost != nil && k.Mode == "gost" {
		if e = k.Gost.WaitReady(20 * time.Second); e != nil {
			log.Fatal(e)
		}
	}
	m, e := engine.New(c.StatePath, &k)
	if e != nil {
		log.Fatal(e)
	}
	if *testFault != "" {
		if !c.AllowInsecure {
			log.Fatal("fault injection is disabled outside isolated tests")
		}
		if _, e = os.Stat("/run/flux-test-disposable"); e != nil {
			log.Fatal("fault injection requires the disposable container marker")
		}
		if *testFault == "mode-reject" {
			m.ModeFailure = func() error { return fmt.Errorf("injected mode activation failure") }
		}
		m.Fault = func(stage string) {
			if stage == *testFault {
				os.Exit(82)
			}
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *helperMode {
		if c.HelperSocket == "" {
			log.Fatal("kernel helper requires helperSocket")
		}
		numeric := *helperUser
		if _, err := strconv.ParseUint(numeric, 10, 32); err != nil {
			account, err := user.Lookup(numeric)
			if err != nil {
				log.Fatal("helper account unavailable")
			}
			numeric = account.Uid
		}
		uid, err := control.HelperUID(numeric)
		if err != nil {
			log.Fatal("invalid helper account")
		}
		m.ConfigureResolver(c.DNSServers)
		if e = control.ServeHelper(ctx, c.HelperSocket, uid, m); e != nil {
			log.Fatal(e)
		}
		return
	}
	if e = control.Run(ctx, c, m); e != nil {
		log.Fatal(e)
	}
}
