package client

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/howeyc/gopass"
	log "github.com/sirupsen/logrus"
	"github.com/walkert/cipher"
	pb "github.com/walkert/gatekeeper/gateproto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

var testPass []byte

type Client struct {
	c      pb.VaultClient
	config string
}

func (c *Client) readConfig() string {
	data, err := ioutil.ReadFile(c.config)
	if err != nil {
		log.Fatalf("unable to read %s: %v\n", c.config, err)
	}
	return string(data)
}

func (c *Client) writeConfig(data string) {
	file, err := os.Create(c.config)
	if err != nil {
		log.Fatalf("unable to create %s: %v\n", c.config, err)
	}
	defer file.Close()
	file.WriteString(data)
}

func (c *Client) getMetaContext() context.Context {
	data := c.readConfig()
	salt := data[:len(data)/2]
	auth := base64.StdEncoding.EncodeToString([]byte(salt))
	md := metadata.Pairs("auth", auth)
	return metadata.NewOutgoingContext(context.Background(), md)
}

func (c *Client) readPasswordFromUser() []byte {
	var (
		err  error
		pass []byte
	)
	if len(testPass) != 0 {
		pass = testPass
	} else {
		fmt.Printf("Password: ")
		pass, err = gopass.GetPasswdMasked()
		if err != nil {
			log.Fatalf("unable to get password from user: %v\n", err)
		}
	}
	random := cipher.RandomString(30)
	salt := random[:len(random)/2]
	encPass := random[len(random)/2:]
	data, err := cipher.EncryptString(string(pass), salt, encPass)
	if err != nil {
		log.Fatalf("unable to encrypt password: %v\n", err)
	}
	c.writeConfig(random)
	return data
}

func (c *Client) GetPassword() string {
	ctx := c.getMetaContext()
	result, err := c.c.Get(ctx, &pb.Void{})
	if err != nil {
		log.Fatalf("unable to GET: %v\n", err)
	}
	configString := c.readConfig()
	salt := configString[:len(configString)/2]
	encPass := configString[len(configString)/2:]
	password, err := cipher.DecryptBytes(result.GetPassword(), salt, encPass)
	if err != nil {
		log.Fatal(err)
	}
	return string(password)
}

func (c *Client) SetPassword() {
	data := c.readPasswordFromUser()
	ctx := c.getMetaContext()
	_, err := c.c.Set(ctx, &pb.Payload{Password: data, Auth: ""})
	if err != nil {
		log.Fatalf("unable to set password: %v\n", err)
	}
}

func New(port int, configFile, certFile string) *Client {
	var opt grpc.DialOption
	if certFile != "" {
		creds, err := credentials.NewClientTLSFromFile(certFile, "")
		if err != nil {
			log.Fatalf("unable to set tls: %v\n", err)
		}
		opt = grpc.WithTransportCredentials(creds)
	} else {
		opt = grpc.WithInsecure()
	}
	conn, err := grpc.Dial(fmt.Sprintf("localhost:%d", port), opt)
	if err != nil {
		log.Fatalf("did not connect: %v\n", err)
	}
	return &Client{c: pb.NewVaultClient(conn), config: configFile}
}
