package server

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/walkert/cipher"
	pb "github.com/walkert/stash/stashproto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

var (
	encPass         string
	masterPassword  []byte
	mux             sync.Mutex
	salt            string
	watchDogRunning bool
)

type vault struct{}

func (v *vault) Get(ctx context.Context, void *pb.Void) (*pb.Payload, error) {
	if p, ok := peer.FromContext(ctx); ok {
		log.Debugf("Recevied GET request from %s\n", p.Addr)
	}
	if len(masterPassword) == 0 {
		return &pb.Payload{}, grpc.Errorf(codes.NotFound, "password not set")
	}
	decrypted, err := decryptPass()
	if err != nil {
		return &pb.Payload{}, err
	}
	return &pb.Payload{Password: decrypted}, nil
}

func (v *vault) Set(ctx context.Context, payload *pb.Payload) (*pb.Void, error) {
	if p, ok := peer.FromContext(ctx); ok {
		log.Debugf("Recevied SET request from %s\n", p.Addr)
	}
	encryptPass(payload.GetPassword())
	if !watchDogRunning {
		go watchDog()
		watchDogRunning = true
	}
	return &pb.Void{}, nil
}

type Server struct {
	clientAuth  string
	l           net.Listener
	expiration  time.Duration
	host        string
	passwordSet bool
	port        int
	s           *grpc.Server
}

func watchDog() {
	timer := time.NewTicker(time.Second * 5)
	for {
		now := <-timer.C
		// Stop the watchdog when there's no longer a password set
		if len(masterPassword) == 0 {
			log.Debug("Stopping the watchdog at", now)
			return
		}
		current, _ := decryptPass()
		encryptPass(current)
	}
}

func encryptPass(password []byte) error {
	mux.Lock()
	defer mux.Unlock()
	salt = cipher.RandomString(12)
	encPass = cipher.RandomString(32)
	data, err := cipher.EncryptBytes(password, salt, encPass)
	if err != nil {
		return err
	}
	masterPassword = data
	return nil
}

func decryptPass() ([]byte, error) {
	mux.Lock()
	defer mux.Unlock()
	data, err := cipher.DecryptBytes(masterPassword, salt, encPass)
	if err != nil {
		return []byte{}, fmt.Errorf("unable to decrypt password data: %v\n", err)
	}
	return data, nil
}

func (s *Server) AuthInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	meta, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, grpc.Errorf(codes.Unauthenticated, "missing context header")
	}
	if len(meta["auth"]) != 1 {
		return nil, grpc.Errorf(codes.Unauthenticated, "invalid auth token")
	}
	value := meta["auth"][0]
	if info.FullMethod == "/stashproto.Stash/Get" {
		if s.passwordSet {
			if value != s.clientAuth {
				return nil, grpc.Errorf(codes.Unauthenticated, "invalid auth token")
			}
		}
	}
	if info.FullMethod == "/stashproto.Stash/Set" {
		s.clientAuth = value
		s.passwordSet = true
	}
	return handler(ctx, req)
}

func New(host string, port int, certFile, keyFile string, expiration int) (*Server, error) {
	svr := &Server{host: host, port: port, expiration: time.Hour * time.Duration(expiration)}
	options := []grpc.ServerOption{grpc.UnaryInterceptor(svr.AuthInterceptor)}
	if certFile != "" && keyFile != "" {
		creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
		if err != nil {
			return &Server{}, fmt.Errorf("unable to set tls: %v", err)
		}
		options = append(options, grpc.Creds(creds))
	}
	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return &Server{}, fmt.Errorf("failed to listen: %v", err)
	}
	s := grpc.NewServer(options...)
	pb.RegisterStashServer(s, &vault{})
	svr.l = lis
	svr.s = s
	return svr, nil
}

func (s *Server) Start() error {
	if s.expiration > 0 {
		go func() {
			timer := time.NewTicker(s.expiration)
			for {
				now := <-timer.C
				log.Debugln("Dropping the password at", now)
				s.clientAuth = ""
				s.passwordSet = false
				masterPassword = nil
			}
		}()
	}
	log.Debugf("grpc server listening on: %s:%d\n", s.host, s.port)
	if err := s.s.Serve(s.l); err != nil {
		return fmt.Errorf("unable to server: %v", err)
	}
	return nil
}

func (s *Server) Stop() {
	s.s.Stop()
}
