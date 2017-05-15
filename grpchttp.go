// Copyright © 2017 Saquib Mian <saquib.mian@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package grpchttp

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"

	"github.com/elazarl/go-bindata-assetfs"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/saquibmian/grpchttp/swagger"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Config struct {
	Port                   int
	Address                string
	RootCAs                *x509.CertPool
	Cert                   *tls.Certificate
	ServerOptions          []grpc.ServerOption
	DialOptions            []grpc.DialOption
	RegisterServices       func(*grpc.Server) error
	RegisterGatewayHandler func(context.Context, *runtime.ServeMux, string, []grpc.DialOption) error
	SwaggerJSON            string
}

type GRPCHTTP interface {
	ListenAndServe() error
}

type grpchttp struct {
	config     Config
	grpcServer *grpc.Server
	httpMux    *http.ServeMux
}

func (g *grpchttp) ListenAndServe() error {
	httpServer := &http.Server{
		Addr:    g.config.Address,
		Handler: mainHandler(g.grpcServer, g.httpMux),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*g.config.Cert},
			NextProtos:   []string{"h2"},
		},
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", g.config.Port))
	if err != nil {
		return err
	}

	fmt.Printf("serving http and grpc on port %d\n", g.config.Port)
	err = httpServer.Serve(tls.NewListener(listener, httpServer.TLSConfig))
	return err
}

func NewGRPCHTTP(config Config) (GRPCHTTP, error) {
	// create and initialize gRPC server
	serverOpts := []grpc.ServerOption{
		grpc.Creds(credentials.NewClientTLSFromCert(config.RootCAs, config.Address)),
	}
	serverOpts = append(serverOpts, config.ServerOptions...)
	grpcServer := grpc.NewServer(serverOpts...)
	err := config.RegisterServices(grpcServer)
	if err != nil {
		return nil, err
	}

	// set up the grpcgateway mux
	gatewayMux := runtime.NewServeMux()
	tlsCreds := credentials.NewTLS(&tls.Config{
		ServerName: config.Address,
		RootCAs:    config.RootCAs,
	})
	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(tlsCreds),
	}
	dialOpts = append(dialOpts, config.DialOptions...)
	err = config.RegisterGatewayHandler(context.Background(), gatewayMux, config.Address, dialOpts)
	if err != nil {
		return nil, err
	}

	// set up the http mux
	httpMux := http.NewServeMux()
	httpMux.Handle("/", gatewayMux)
	// serve swagger if configured
	if config.SwaggerJSON != "" {
		handleSwagger(httpMux, config.SwaggerJSON)
	}

	return &grpchttp{
		config:     config,
		grpcServer: grpcServer,
		httpMux:    httpMux,
	}, nil
}

// mainHandler returns an http.Handler that delegates to grpcServer on incoming gRPC
// connections or otherHandler otherwise.
func mainHandler(grpcServer *grpc.Server, otherHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This is a partial recreation of gRPC's internal checks https://github.com/grpc/grpc-go/blob/master/transport/handler_server.go#L62
		if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
		} else {
			otherHandler.ServeHTTP(w, r)
		}
	})
}

func handleSwagger(httpMux *http.ServeMux, swaggerJSON string) {
	mime.AddExtensionType(".svg", "image/svg+xml")

	// expose /swagger.json
	httpMux.HandleFunc("/swagger.json", func(w http.ResponseWriter, req *http.Request) {
		io.Copy(w, strings.NewReader(swaggerJSON))
	})

	// expose /swagger-ui/
	prefix := "/swagger-ui/"
	fs := http.FileServer(&assetfs.AssetFS{
		Asset:    swagger.Asset,
		AssetDir: swagger.AssetDir,
	})
	httpMux.Handle(prefix, http.StripPrefix(prefix, fs))
}
