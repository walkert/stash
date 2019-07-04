package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"sync"
	"time"

	"github.com/howeyc/gopass"
	"github.com/mitchellh/go-homedir"
	flag "github.com/spf13/pflag"
	"github.com/walkert/cipher"
	pb "github.com/walkert/gatekeeper/gateproto"
	"google.golang.org/grpc"
)

const (
	port     = 2002
	confName = ".gkeeper"
)

var (
	auth           string
	client         pb.VaultClient
	configFile     string
	encPass        string
	masterPassword []byte
	mux            sync.Mutex
	salt           string
)

type vault struct{}

func (v *vault) Get(ctx context.Context, void *pb.Void) (*pb.Payload, error) {
	return &pb.Payload{Password: decryptPass(), Auth: auth}, nil
}

func (v *vault) Set(ctx context.Context, payload *pb.Payload) (*pb.Void, error) {
	encryptPass(payload.GetPassword())
	go watchDog()
	return &pb.Void{}, nil
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

func decryptPass() []byte {
	mux.Lock()
	defer mux.Unlock()
	data, err := cipher.DecryptBytes(masterPassword, salt, encPass)
	if err != nil {
		fmt.Println("can't decrypt", err)
		return []byte{}
	}
	return data
}

func mytest() {
	salt := "test"
	pass := "somepassword"
	mypass := "TESTme"
	data, err := cipher.EncryptBytes([]byte(mypass), salt, pass)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Data before enc:", data)
	out, err := cipher.DecryptBytes(data, salt, pass)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Data after enc:", data)
	fmt.Println("1:", string(out))
	out, err = cipher.DecryptBytes(data, salt, pass)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("2:", string(out))
}

func setConfig() {
	dir, _ := homedir.Dir()
	configFile = path.Join(dir, confName)
}

func writeConfig(data string) {
	file, err := os.Create(configFile)
	if err != nil {
		log.Fatalf("unable to create %s: %v\n", configFile, err)
	}
	defer file.Close()
	file.WriteString(data)
}

func readConfig() string {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatalf("unable to create %s: %v\n", configFile, err)
	}
	return string(data)
}

func readPasswordFromUser() []byte {
	fmt.Printf("Password: ")
	pass, err := gopass.GetPasswdMasked()
	if err != nil {
		log.Fatalf("unable to get password from user: %v\n", err)
	}
	random := cipher.RandomString(30)
	salt := random[:len(random)/2]
	encPass := random[len(random)/2:]
	fmt.Println("using salt, pass:", salt, encPass)
	data, err := cipher.EncryptString(string(pass), salt, encPass)
	if err != nil {
		log.Fatalf("unable to encrypt password: %v\n", err)
	}
	writeConfig(random)
	return data
}

func getPassword(c pb.VaultClient) {
	result, err := c.Get(context.Background(), &pb.Void{})
	if err != nil {
		log.Fatalf("unable to GET: %v\n", err)
	}
	configString := readConfig()
	salt := configString[:len(configString)/2]
	encPass := configString[len(configString)/2:]
	fmt.Println("using salt, pass:", salt, encPass)
	fmt.Println("Got bytes:", result.GetPassword())
	password, err := cipher.DecryptBytes(result.GetPassword(), salt, encPass)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Password:", string(password))
}

func main() {
	asClient := flag.Bool("client", false, "run in client mode")
	get := flag.Bool("get", false, "get data")
	server := flag.Bool("server", false, "run in server mode")
	set := flag.Bool("set", false, "set the password")
	flag.Parse()
	setConfig()
	if *asClient {
		conn, err := grpc.Dial(fmt.Sprintf("localhost:%d", port), grpc.WithInsecure())
		if err != nil {
			log.Fatalf("did not connect: %v\n", err)
		}
		defer conn.Close()
		client = pb.NewVaultClient(conn)
		if *get {
			getPassword(client)
		}
		if *set {
			data := readPasswordFromUser()
			client.Set(context.Background(), &pb.Payload{Password: data, Auth: ""})
		}
	}

	if *server {
		salt = cipher.RandomString(12)
		encPass = cipher.RandomString(32)
		lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
		if err != nil {
			log.Fatalf("failed to listen: %v\n", err)
		}
		s := grpc.NewServer()
		pb.RegisterVaultServer(s, &vault{})
		fmt.Printf("grpc server listening on: %d\n", port)
		if err := s.Serve(lis); err != nil {
			log.Fatalf("unable to server: %v\n", err)
		}
	}
}
