package main

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/dgrijalva/jwt-go"
	pb "github.com/joeyparsons/grpc-nog/nog"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

func validateToken(token string, publicKey *rsa.PublicKey) (*jwt.Token, error) {
	jwtToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			log.Printf("Unexpected signing method: %v", t.Header["alg"])
			return nil, fmt.Errorf("invalid token")
		}
		return publicKey, nil
	})
	if err == nil && jwtToken.Valid {
		return jwtToken, nil
	}
	return nil, err
}

type nogServer struct {
	jwtPublicKey *rsa.PublicKey
}

func NewNogServer(rsaPublicKey string) (*nogServer, error) {
	data, err := ioutil.ReadFile(rsaPublicKey)
	if err != nil {
		return nil, fmt.Errorf("Error reading the jwt public key: %v", err)
	}

	publickey, err := jwt.ParseRSAPublicKeyFromPEM(data)
	if err != nil {
		return nil, fmt.Errorf("Error reading the jwt public key: %v", err)
	}

	return &nogServer{publickey}, nil
}

func (ns *nogServer) Say(ctx context.Context, request *pb.Request) (*pb.Response, error) {
	var (
		token *jwt.Token
		err   error
	)

	md, ok := metadata.FromContext(ctx)
	if !ok {
		return nil, grpc.Errorf(codes.Unauthenticated, "valid token required.")
	}

	jwtToken, ok := md["authorization"]
	if !ok {
		return nil, grpc.Errorf(codes.Unauthenticated, "valid token required.")
	}

	token, err = validateToken(jwtToken[0], ns.jwtPublicKey)
	if err != nil {
		return nil, grpc.Errorf(codes.Unauthenticated, "valid token required.")
	}

	response := &pb.Response{
		Message: fmt.Sprintf("Hello %s (%s)", request.Name, token.Claims["email"]),
	}

	return response, nil
}

func main() {
	fmt.Println("vim-go")
}
