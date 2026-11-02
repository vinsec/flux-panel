package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/x/api"
	"github.com/go-gost/x/config/parsing/parser"
	"github.com/go-gost/x/registry"
	"github.com/go-gost/x/service"
)

// The supervisor owns registration and accounting. This endpoint is local,
// protected by Unix credentials/filesystem permissions, and has no panel secret.
func runManaged() error {
	if !filepath.IsAbs(managedSocket) || len(managedSocket) > 100 || cfgFile == "" {
		return fmt.Errorf("managed mode requires an absolute Unix socket and explicit -C config")
	}
	if _, e := os.Lstat(managedSocket); e == nil {
		return fmt.Errorf("managed socket already exists")
	}
	service.SetAgentManaged(true)
	parser.Init(parser.Args{CfgFile: cfgFile})
	p := &program{}
	if e := p.Start(); e != nil {
		return e
	}
	defer p.Stop()
	listener, e := net.Listen("unix", managedSocket)
	if e != nil {
		return e
	}
	defer listener.Close()
	defer os.Remove(managedSocket)
	if e = os.Chmod(managedSocket, 0660); e != nil {
		return e
	}
	gin.SetMode(gin.ReleaseMode)
	b := make([]byte, 16)
	if _, e = rand.Read(b); e != nil {
		return e
	}
	generation := hex.EncodeToString(b)
	router := gin.New()
	router.GET("/agent/health", func(c *gin.Context) {
		names := []string{}
		for name := range registry.ServiceRegistry().GetAll() {
			names = append(names, name)
		}
		c.JSON(200, map[string]any{"generation": generation, "managed": true, "services": names})
	})
	api.Register(router, nil)
	server := &http.Server{Handler: router, ReadHeaderTimeout: 5e9}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
		return server.Close()
	case e := <-done:
		return e
	}
}
