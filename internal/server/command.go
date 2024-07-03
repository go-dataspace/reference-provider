// Copyright 2024 go-dataspace
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package server provides the server subcommand.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/go-dataspace/reference-provider/internal/authprocessor"
	"github.com/go-dataspace/reference-provider/internal/cli"
	"github.com/go-dataspace/reference-provider/internal/fsprovider"
	"github.com/go-dataspace/run-dsp/logging"
	providerv1 "github.com/go-dataspace/run-dsrpc/gen/go/provider/v1"
	grpclog "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

//nolint:lll
type Command struct {
	// Generic settings
	FileRoot string `help:"Root to scan for files" default:"/var/lib/run-dsp/fsprovider"`

	// GRPC settings
	GRPCListenAddr               string `help:"Listen address for the GRPC service" default:"0.0.0.0" env:"GRPC_LISTEN_ADDR"`
	GRPCPort                     int    `help:"Port for the GRPC service" default:"9090" env:"GRPC_PORT"`
	GRPCInsecure                 bool   `help:"Disable TLS" default:"false" env:"PROVIDER_INSECURE"`
	GRPCCert                     string `help:"Client certificate to use to authenticate with provider" env:"PROVIDER_CLIENT_CERT"`
	GRPCCertKey                  string `help:"Key to the client certificate" env:"PROVIDER_CLIENT_CERT_KEY"`
	GRPCVerifyClientCertificates bool   `help:"Require validated client certificates to connect" default:"false" env:"GRPC_VERIFY_CLIENT_CERTIFICATES" `
	GRPCClientCACert             string `help:"Custom CA certificate to verify client certificates with" env:"PROVIDER_CA"`

	// File publish settings
	PublishListenAddr string `help:"Listen address for the file publish service." default:"0.0.0.0" env:"PUBLISH_LISTEN_ADDR"`
	PublishPort       int    `help:"Port for the file publish service." default:"9091" env:"PUBLISH_PORT"`
	ExternalURL       string `help:"External address that the publish service is reachable from." default:"http://127.0.0.1:9091/" env:"EXTERNAL_URL"`
}

func (c *Command) Validate() error {
	_, err := checkFile(c.FileRoot, true)
	if err != nil {
		return fmt.Errorf("file-root: %w", err)
	}

	if c.GRPCInsecure {
		return nil
	}

	certSupplied, err := checkFile(c.GRPCCert, false)
	if err != nil {
		return fmt.Errorf("GRPC certificate: %w", err)
	}
	keySupplied, err := checkFile(c.GRPCCertKey, false)
	if err != nil {
		return fmt.Errorf("GRPC certificate key: %w", err)
	}

	if !certSupplied {
		return fmt.Errorf("GRPC certificate not supplied")
	}

	if !keySupplied {
		return fmt.Errorf("GRPC certificate key not supplied")
	}

	if c.GRPCVerifyClientCertificates {
		caSupplied, err := checkFile(c.GRPCClientCACert, false)
		if err != nil {
			return fmt.Errorf("GRPC client CA certificate: %w", err)
		}
		if !caSupplied {
			return fmt.Errorf("GRPC client CA certificate required when using client cert auth")
		}
	}

	return nil
}

func checkFile(l string, wantDir bool) (bool, error) {
	if l != "" {
		f, err := os.Stat(l)
		if err != nil {
			return true, fmt.Errorf("could not read %s: %w", l, err)
		}
		if f.IsDir() != wantDir {
			return true, fmt.Errorf("%s is a directory", l)
		}
		return true, nil
	}
	return false, nil
}

func (c *Command) Run(p cli.Params) error {
	ctx, cancel := signal.NotifyContext(p.Context(), os.Interrupt, os.Kill)
	defer cancel()

	logger := logging.Extract(ctx)
	logger.Info("Starting up",
		"file_root", c.FileRoot,
		"grpc_addr", c.GRPCListenAddr,
		"grpc_port", c.GRPCPort,
		"publish_addr", c.PublishListenAddr,
		"publish_port", c.PublishPort,
		"external_url", c.ExternalURL,
	)

	extURL, err := url.Parse(c.ExternalURL)
	if err != nil {
		return fmt.Errorf("invalid external URL %s: %w", c.ExternalURL, err)
	}

	wg := &sync.WaitGroup{}

	fsProvider, err := fsprovider.New(ctx, c.FileRoot, extURL)
	if err != nil {
		return fmt.Errorf("couldn't start FS provider: %w", err)
	}

	err = c.startGRPC(ctx, wg, fsProvider)
	if err != nil {
		return err
	}

	err = c.startPublish(ctx, wg, fsProvider)
	if err != nil {
		return err
	}

	wg.Wait()
	return nil
}

func (c *Command) startGRPC(ctx context.Context, wg *sync.WaitGroup, fsp *fsprovider.Server) error {
	wg.Add(1)
	logger := logging.Extract(ctx).With("grpc_addr", c.GRPCListenAddr, "grpc_port", c.GRPCPort)

	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", c.GRPCListenAddr, c.GRPCPort))
	if err != nil {
		return fmt.Errorf("failed to listen on %s:%d: %w", c.GRPCListenAddr, c.GRPCPort, err)
	}

	tlsCredentials, err := c.loadTLSCredentials()
	if err != nil {
		return fmt.Errorf("could not load TLS credentials: %w", err)
	}

	logOpts := []grpclog.Option{
		grpclog.WithLogOnEvents(grpclog.StartCall, grpclog.FinishCall),
	}
	grpcServer := grpc.NewServer(
		grpc.Creds(tlsCredentials),
		grpc.ChainUnaryInterceptor(
			grpclog.UnaryServerInterceptor(interceptorLogger(logger), logOpts...),
			authprocessor.UnaryInterceptor,
		),
		grpc.ChainStreamInterceptor(
			grpclog.StreamServerInterceptor(interceptorLogger(logger), logOpts...),
			authprocessor.StreamInterceptor,
		),
	)
	providerv1.RegisterProviderServiceServer(grpcServer, fsp)

	go func() {
		logger.Info("Starting GRPC service")
		if err := grpcServer.Serve(lis); err != nil {
			logger.Error("GRPC service exited with error", "error", err)
		}
		logger.Info("GRPC service shutdown.")
	}()

	// Wait until we get the done signal and then shut down the grpc service.
	go func() {
		defer wg.Done()
		<-ctx.Done()
		logger.Info("Shutting down GRPC service.")
		grpcServer.GracefulStop()
	}()
	return nil
}

func (c *Command) loadTLSCredentials() (credentials.TransportCredentials, error) {
	if c.GRPCInsecure {
		return insecure.NewCredentials(), nil
	}

	serverCert, err := tls.LoadX509KeyPair(c.GRPCCert, c.GRPCCertKey)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
	}

	if c.GRPCVerifyClientCertificates {
		pemServerCA, err := os.ReadFile(c.GRPCClientCACert)
		if err != nil {
			return nil, fmt.Errorf("couldn't read CA file: %w", err)
		}

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(pemServerCA) {
			return nil, fmt.Errorf("failed to add server CA certificate")
		}
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = certPool
	}

	return credentials.NewTLS(config), nil
}

func (c *Command) startPublish(ctx context.Context, wg *sync.WaitGroup, fsp *fsprovider.Server) error {
	defer wg.Done()
	wg.Add(1)
	logger := logging.Extract(ctx).With("publish_addr", c.PublishListenAddr, "publish_port", c.PublishPort)

	mux := http.NewServeMux()
	mux.Handle("/", fsp.Mux())
	srv := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", c.PublishListenAddr, c.PublishPort),
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
	}
	go func() {
		logger.Info("Starting publish service")
		if err := srv.ListenAndServe(); err != nil {
			logger.Error("Publish service exited with error", "error", err)
		}
		logger.Info("Publish service shutdown")
	}()

	// Wait until we get the done signal and then shut down the publish service.
	go func() {
		defer wg.Done()
		<-ctx.Done()
		tctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()
		logger.Info("Shutting down publish server.")
		if err := srv.Shutdown(tctx); err != nil {
			logger.Error("Publish service failed shutting down.", "error", err)
		}
		logger.Info("Finished shutting down publish server.")
	}()
	return nil
}

func interceptorLogger(l *slog.Logger) grpclog.Logger {
	return grpclog.LoggerFunc(func(ctx context.Context, lvl grpclog.Level, msg string, fields ...any) {
		l.Log(ctx, slog.Level(lvl), msg, fields...)
	})
}
