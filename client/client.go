package client

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/howeyc/gopass"
	"github.com/walkert/cipher"
	pb "github.com/walkert/gatekeeper/gateproto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

var TestPass []byte

type Client struct {
	c      pb.VaultClient
	config string
}

func (c *Client) readConfig() (string, error) {
	data, err := ioutil.ReadFile(c.config)
	if err != nil {
		return "", fmt.Errorf("unable to read %s: %v\n", c.config, err)
	}
	return string(data), nil
}

func (c *Client) writeConfig(data string) error {
	file, err := os.Create(c.config)
	if err != nil {
		return fmt.Errorf("unable to create %s: %v\n", c.config, err)
	}
	defer file.Close()
	file.WriteString(data)
	return nil
}

func (c *Client) getMetaContext() (context.Context, error) {
	data, err := c.readConfig()
	if err != nil {
		return context.Background(), err
	}
	salt := data[:len(data)/2]
	auth := base64.StdEncoding.EncodeToString([]byte(salt))
	md := metadata.Pairs("auth", auth)
	return metadata.NewOutgoingContext(context.Background(), md), nil
}

func (c *Client) readPasswordFromUser() ([]byte, error) {
	var (
		err  error
		pass []byte
	)
	if len(TestPass) != 0 {
		pass = TestPass
	} else {
		fmt.Printf("Password: ")
		pass, err = gopass.GetPasswdMasked()
		if err != nil {
			return []byte{}, fmt.Errorf("unable to get password from user: %v", err)
		}
	}
	random := cipher.RandomString(30)
	salt := random[:len(random)/2]
	encPass := random[len(random)/2:]
	data, err := cipher.EncryptString(string(pass), salt, encPass)
	if err != nil {
		return []byte{}, fmt.Errorf("unable to encrypt password: %v", err)
	}
	err = c.writeConfig(random)
	if err != nil {
		return []byte{}, err
	}
	return data, nil
}

func (c *Client) GetPassword() (string, error) {
	ctx, err := c.getMetaContext()
	if err != nil {
		return "", err
	}
	result, err := c.c.Get(ctx, &pb.Void{})
	if err != nil {
		return "", fmt.Errorf("unable to get password: %v\n", err)
	}
	configString, err := c.readConfig()
	if err != nil {
		return "", err
	}
	salt := configString[:len(configString)/2]
	encPass := configString[len(configString)/2:]
	password, err := cipher.DecryptBytes(result.GetPassword(), salt, encPass)
	if err != nil {
		return "", fmt.Errorf("error decrypting password: %v\n", err)
	}
	return string(password), nil
}

func (c *Client) SetPassword() error {
	data, err := c.readPasswordFromUser()
	if err != nil {
		return err
	}
	ctx, err := c.getMetaContext()
	if err != nil {
		return err
	}
	_, err = c.c.Set(ctx, &pb.Payload{Password: data, Auth: ""})
	if err != nil {
		return fmt.Errorf("unable to set password: %v", err)
	}
	return nil
}

func New(port int, configFile, certFile string) (*Client, error) {
	var opt grpc.DialOption
	if certFile != "" {
		creds, err := credentials.NewClientTLSFromFile(certFile, "")
		if err != nil {
			return &Client{}, fmt.Errorf("unable to set tls: %v", err)
		}
		opt = grpc.WithTransportCredentials(creds)
	} else {
		opt = grpc.WithInsecure()
	}
	conn, err := grpc.Dial(fmt.Sprintf("localhost:%d", port), opt)
	if err != nil {
		return &Client{}, fmt.Errorf("coult not connect to server: %v\n", err)
	}
	return &Client{c: pb.NewVaultClient(conn), config: configFile}, nil
}
