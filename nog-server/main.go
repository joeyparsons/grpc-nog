package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"

	pb "github.com/joeyparsons/grpc-nog/nog"
	"golang.org/x/net/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"

	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func withConfigDir(path string) string {
	return filepath.Join(os.Getenv("HOME"), ".nog", "server", path)
}

func main() {
	var (
		caCert          = flag.String("ca-cert", withConfigDir("ca.pem"), "Trusted CA Certificate.")
		debugListenAddr = flag.String("debug-listen-addr", "127.0.0.1:7901", "HTTP listen (debug) address.")
		listenAddr      = flag.String("listen-addr", "0.0.0.0:7901", "HTTP listen address.")
		tlsCert         = flag.String("tls-cert", withConfigDir("cert.pem"), "TLS server certificate.")
		tlsKey          = flag.String("tls-key", withConfigDir("key.pem"), "TLS server key.")
		jwtPublicKey    = flag.String("jwt-public-key", withConfigDir("jwt.pem"), "The RSA public key to use for validating JWTs")
	)

	flag.Parse()

	log.Println("Nog service starting...")

	cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
	if err != nil {
		log.Fatal(err)
	}

	rawCaCert, err := ioutil.ReadFile(*caCert)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(rawCaCert)

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})

	gs := grpc.NewServer(grpc.Creds(creds))

	ns, err := NewNogServer(*jwtPublicKey)
	if err != nil {
		log.Fatal(err)
	}

	pb.RegisterNogServer(gs, ns)

	healthServer := health.NewServer()
	healthServer.SetServingStatus("grpc.health.v1.nogservice", 1)
	healthpb.RegisterHealthServer(gs, healthServer)

	ln, err := net.Listen("tpc", *listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	go gs.Serve(ln)

	trace.AuthRequest = func(req *http.Request) (any, sensitive bool) { return true, true }

	log.Println("Nog service started successfully.")
	log.Fatal(http.ListenAndServe(*debugListenAddr, nil))
}
