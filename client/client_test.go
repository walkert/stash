package client

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/walkert/gatekeeper/server"
)

func init() {
	go func() {
		fmt.Println("Started server on 5001")
		server.Start(5001, "", "")
	}()
}

func TestSetGet(t *testing.T) {
	file, err := ioutil.TempFile(os.TempDir(), "")
	if err != nil {
		t.Fatalf("unable to create temp file: %s\n", err)
	}
	defer os.Remove(file.Name())
	log.SetLevel(log.DebugLevel)
	c := New(5001, file.Name(), "")
	testPass = []byte("test")
	c.SetPassword()
	pass := c.GetPassword()
	if pass != "test" {
		t.Fatalf("Wanted: 'test', got: %s\n", pass)
	}
}
