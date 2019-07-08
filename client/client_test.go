package client

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/walkert/gatekeeper/server"
)

func TestSetGet(t *testing.T) {
	s := server.New(5001, "", "")
	go func() {
		s.Start()
	}()
	defer s.Stop()
	file, err := ioutil.TempFile(os.TempDir(), "")
	if err != nil {
		t.Fatalf("unable to create temp file: %s\n", err)
	}
	defer os.Remove(file.Name())
	c := New(5001, file.Name(), "")
	TestPass = []byte("test")
	c.SetPassword()
	pass, err := c.GetPassword()
	if err != nil {
		t.Fatalf("unexpected error while getting password: %v\n", err)
	}
	if pass != "test" {
		t.Fatalf("Wanted: 'test', got: %s\n", pass)
	}
}
