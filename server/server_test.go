package server

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/walkert/gatekeeper/client"
)

func TestServerSetGet(t *testing.T) {
	s, err := New(5002, "", "")
	if err != nil {
		t.Fatalf("problem creating server: %v", err)
	}
	go func() {
		err := s.Start()
		if err != nil {
			t.Fatalf("problem starting server: %v", err)
		}
	}()
	file, err := ioutil.TempFile(os.TempDir(), "")
	if err != nil {
		t.Fatalf("unable to create temp file: %s\n", err)
	}
	defer os.Remove(file.Name())
	c, err := client.New(5002, file.Name(), "")
	if err != nil {
		t.Fatalf("unexpected error while getting client: %v\n", err)
	}
	client.TestPass = []byte("test")
	err = c.SetPassword()
	if err != nil {
		t.Fatalf("unexpected error while setting password: %v\n", err)
	}
	pass, err := c.GetPassword()
	s.Stop()
	if err != nil {
		t.Fatalf("unexpected error while getting password: %v\n", err)
	}
	if pass != "test" {
		t.Fatalf("Wanted: 'test', got: %s\n", pass)
	}
}

func TestServerBadAuth(t *testing.T) {
	s, err := New(5002, "", "")
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
	c, err := client.New(5002, file.Name(), "")
	if err != nil {
		t.Fatalf("unexpected error while getting client: %v\n", err)
	}
	client.TestPass = []byte("test")
	err = c.SetPassword()
	if err != nil {
		t.Fatalf("unexpected error while setting password: %v\n", err)
	}
	// mess with the data in the config file
	file, err = os.Create(file.Name())
	if err != nil {
		t.Fatalf("unable to create %s: %v\n", file.Name(), err)
	}
	defer file.Close()
	file.WriteString("bad")
	_, err = c.GetPassword()
	if err == nil {
		t.Fatalf("expected error but got none")
	}
	if !strings.Contains(err.Error(), "invalid auth token") {
		t.Fatalf("Unexpected error string: %s\n", err.Error())
	}
}
