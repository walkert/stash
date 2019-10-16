package server

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/walkert/stash/client"
)

func TestServerSetGet(t *testing.T) {
	s, err := New("localhost", 5002, "", "", 0)
	if err != nil {
		t.Fatalf("problem creating server: %v", err)
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
	file, err = os.Create(file.Name())
	if err != nil {
		t.Fatalf("unable to create %s: %v\n", file.Name(), err)
	}
	file.WriteString(fmt.Sprintf("random:saltandpasswordstring"))
	file.Close()
	_, err = c.GetPassword()
	if err == nil {
		t.Fatalf("expected error getting empty password but got none")
	}
	if !strings.Contains(err.Error(), "password not set") {
		t.Fatalf("unexpected error while getting empty password")
	}
	client.TestPass = []byte("test")
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

func TestServerVarious(t *testing.T) {
	s, err := New("localhost", 5002, "", "", 0)
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
	// break the auth string
	file, err = os.Create(file.Name())
	if err != nil {
		t.Fatalf("unable to create %s: %v\n", file.Name(), err)
	}
	file.WriteString("bad:saltandpasswordstring")
	file.Close()
	_, err = c.GetPassword()
	if err == nil {
		t.Fatalf("expected error but got none")
	}
	if !strings.Contains(err.Error(), "invalid auth token") {
		t.Fatalf("Unexpected error string: %s\n", err.Error())
	}
}
