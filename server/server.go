package server

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/walkert/cipher"
	pb "github.com/walkert/gatekeeper/gateproto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

var (
	auth            string
	clientAuth      string
	encPass         string
	masterPassword  []byte
	mux             sync.Mutex
	salt            string
	passwordSet     bool
	watchDogRunning bool
)

type vault struct{}

func (v *vault) Get(ctx context.Context, void *pb.Void) (*pb.Payload, error) {
	return &pb.Payload{Password: decryptPass(), Auth: auth}, nil
}

func (v *vault) Set(ctx context.Context, payload *pb.Payload) (*pb.Void, error) {
	encryptPass(payload.GetPassword())
	if !watchDogRunning {
		go watchDog()
		watchDogRunning = true
	}
	return &pb.Void{}, nil
}

func watchDog() {
	timer := time.NewTicker(time.Second * 5)
	for {
		<-timer.C
		current := decryptPass()
		salt = cipher.RandomString(12)
		encPass = cipher.RandomString(32)
		encryptPass(current)
	}
}

func encryptPass(password []byte) error {
	mux.Lock()
	defer mux.Unlock()
	data, err := cipher.EncryptBytes(password, salt, encPass)
	if err != nil {
		return err
	}
	masterPassword = data
	return nil
}

func decryptPass() []byte {
	mux.Lock()
	defer mux.Unlock()
	data, err := cipher.DecryptBytes(masterPassword, salt, encPass)
	if err != nil {
		log.Fatalf("unable to decrypt password data: %v\n")
	}
	return data
}

func AuthInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	meta, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, grpc.Errorf(codes.Unauthenticated, "missing context header")
	}
	if len(meta["auth"]) != 1 {
		return nil, grpc.Errorf(codes.Unauthenticated, "invalid auth token")
	}
	value := meta["auth"][0]
	if passwordSet {
		if value != clientAuth {
			return nil, grpc.Errorf(codes.Unauthenticated, "invalid auth token")
		}
	}
	if info.FullMethod == "/gateproto.Vault/Set" {
		clientAuth = value
		passwordSet = true
	}
	return handler(ctx, req)
}

func Start(port int, certFile, keyFile string) {
	creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
	if err != nil {
		log.Fatalf("unable to set tls: %v\n", err)
	}
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		log.Fatalf("failed to listen: %v\n", err)
	}
	s := grpc.NewServer(
		grpc.Creds(creds),
		grpc.UnaryInterceptor(AuthInterceptor),
	)
	pb.RegisterVaultServer(s, &vault{})
	log.Debugf("grpc server listening on: %d\n", port)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("unable to server: %v\n", err)
	}
}
