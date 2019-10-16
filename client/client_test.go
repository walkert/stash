package client

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/walkert/stash/server"
)

func TestSetGet(t *testing.T) {
	s, err := server.New("localhost", 5001, "", "", 0)
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
	current, _ := ioutil.ReadFile(file.Name())
	// break the salt
	spl := strings.Split(string(current), ":")
	file, err = os.Create(file.Name())
	if err != nil {
		t.Fatalf("unable to create %s: %v\n", file.Name(), err)
	}
	file.WriteString(fmt.Sprintf("%s:badSaltandpasswordstring", spl[0]))
	file.Close()
	_, err = c.GetPassword()
	if err == nil {
		t.Fatalf("expected error but got none")
	}
	if !strings.Contains(err.Error(), "data could not be decrypted") {
		t.Fatalf("Unexpected error string: %s\n", err.Error())
	}
}
