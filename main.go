package main

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"syscall"

	"github.com/mitchellh/go-homedir"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
	"github.com/walkert/stash/client"
	"github.com/walkert/stash/server"
)

const (
	certName = ".stash.cert.pem"
	keyName  = ".stash.key.pem"
	confName = ".stash"
)

var (
	auth       string
	certFile   string
	clientAuth string
	configFile string
	keyFile    string
	port       int
	verbose    bool
)

func setConfig() {
	dir, _ := homedir.Dir()
	configFile = path.Join(dir, confName)
	if certFile == "" {
		certFile = path.Join(dir, certName)
	}
	if keyFile == "" {
		keyFile = path.Join(dir, keyName)
	}
	if verbose {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:          true,
		TimestampFormat:        "2006-01-02 15:04:05",
		DisableLevelTruncation: true,
	},
	)
}

func main() {
	asClient := flag.Bool("client", true, "run in client mode")
	daemon := flag.Bool("daemon", false, "run the server as a daemon")
	asServer := flag.Bool("server", false, "run in server mode")
	flag.StringVar(&certFile, "cert-file", "", "the TLS certificate file to use")
	get := flag.Bool("get", false, "get data")
	help := flag.Bool("help", false, "show help")
	flag.StringVar(&keyFile, "key-file", "", "the TLS key file to use")
	flag.IntVar(&port, "port", 2002, "The daemon will listen on this local port")
	set := flag.Bool("set", false, "set the password")
	flag.BoolVar(&verbose, "verbose", false, "enable debugging")
	flag.Parse()
	setConfig()
	prog := path.Base(os.Args[0])
	if *help {
		flag.Usage()
		os.Exit(0)
	}
	if *asServer {
		if *daemon {
			binary, _ := exec.LookPath(os.Args[0])
			cmdEnv := os.Environ()
			pid, err := syscall.ForkExec(binary, []string{binary, "--server"}, &syscall.ProcAttr{Env: cmdEnv})
			if err != nil {
				log.Fatalf("ERROR: unable to start %s in daemon mode: %v\n", prog, err)
			}
			fmt.Printf("Started %s in daemon mode with pid %d\n", prog, pid)
			os.Exit(0)
		}
		s, err := server.New(port, certFile, keyFile)
		if err != nil {
			log.Fatalf("Can't start server: %v\n", err)
		}
		s.Start()
	}
	if *asClient {
		c, err := client.New(port, configFile, certFile)
		if err != nil {
			log.Fatalf("ERROR: %v\n", err)
		}
		if *get {
			out, err := c.GetPassword()
			if err != nil {
				log.Fatalf("ERROR: %v\n", err)
			}
			fmt.Println(string(out))
		}
		if *set {
			err := c.SetPassword()
			if err != nil {
				log.Fatalf("ERROR: %v\n", err)
			}
		}
	}
}
