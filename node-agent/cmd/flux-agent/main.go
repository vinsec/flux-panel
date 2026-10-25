package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/vinsec/flux-panel/node-agent/internal/control"
	"github.com/vinsec/flux-panel/node-agent/internal/engine"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

func main() {
	config := flag.String("config", "config.json", "configuration file")
	plan := flag.String("plan", "", "render a single ForwardSpec without executing commands")
	flag.Parse()
	if *plan != "" {
		b, e := os.ReadFile(*plan)
		if e != nil {
			log.Fatal(e)
		}
		var s engine.Spec
		if e = json.Unmarshal(b, &s); e != nil {
			log.Fatal(e)
		}
		if e = s.Validate(); e != nil {
			log.Fatal(e)
		}
		b, _ = json.MarshalIndent(engine.Render(map[string]engine.Spec{s.ID: s}, nil), "", "  ")
		fmt.Println(string(b))
		return
	}
	b, e := os.ReadFile(*config)
	if e != nil {
		log.Fatal(e)
	}
	var c control.Config
	if e = json.Unmarshal(b, &c); e != nil {
		log.Fatal(e)
	}
	if c.Secret == "" || !c.Apply || c.StatePath == "" {
		log.Fatal("secret, statePath and explicit apply=true are required")
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
	if c.Iptables == "" {
		c.Iptables = "iptables"
	}
	if c.Iptables != "iptables" && c.Iptables != "iptables-nft" && c.Iptables != "iptables-legacy" {
		log.Fatal("unsupported iptables binary")
	}
	k := engine.IPTables{Binary: c.Iptables}
	if e = k.Initialize(); e != nil {
		log.Fatal(e)
	}
	m, e := engine.New(c.StatePath, k)
	if e != nil {
		log.Fatal(e)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if e = control.Run(ctx, c, m); e != nil {
		log.Fatal(e)
	}
}
