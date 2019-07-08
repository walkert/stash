package client

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/walkert/gatekeeper/server"
)

func TestSetGet(t *testing.T) {
	s, err := server.New(5001, "", "")
	if err != nil {
		t.Fatalf("problem starting server: %v", err)
	}
	go func() {
		err := s.Start()
		if err != nil {
			t.Fatalf("problem starting server: %v", err)
		}
	}()
	defer s.Stop()
	file, err := ioutil.TempFile(os.TempDir(), "")
	if err != nil {
		t.Fatalf("unable to create temp file: %s\n", err)
	}
	defer os.Remove(file.Name())
	c, err := New(5001, file.Name(), "")
	if err != nil {
		t.Fatalf("unexpected error while getting client: %v\n", err)
	}
	TestPass = []byte("test")
	err = c.SetPassword()
	if err != nil {
		t.Fatalf("unexpected error while setting password: %v\n", err)
	}
	pass, err := c.GetPassword()
	if err != nil {
		t.Fatalf("unexpected error while getting password: %v\n", err)
	}
	if pass != "test" {
		t.Fatalf("Wanted: 'test', got: %s\n", pass)
	}
}
