# grpchttp

grpchttp is a server that can serve both gRPC and the grpc-web-gateway JSON proxy on the same connection.

## how to use it

Here is a code sample:

```go
certPool := x509.NewCertPool()
pair, err := tls.X509KeyPair([]byte(Cert), []byte(Key))
if err != nil {
    log.Fatalf(err)
}

config := grpchttp.Config{
    Port:        port,
    Address:     addr,
    Cert:        &pair,
    RootCAs:     certPool,
    SwaggerJSON: api.Swagger,
    RegisterServices: func(s *grpc.Server) error {
        // register your gRPC services here
    },
    RegisterGatewayHandler: // this is your grpc-web-gateway service handler,
}

mux, err := grpchttp.NewGRPCHTTP(config)
if err != nil {
    log.Fatalf(err)
}
err = mux.ListenAndServe()
log.Fatalf(err)
```
