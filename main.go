package main

import (
	"fmt"
	"path"

	"github.com/mitchellh/go-homedir"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
	"github.com/walkert/gatekeeper/client"
	"github.com/walkert/gatekeeper/server"
)

const (
	port     = 2002
	certName = ".gkeeper.cert.pem"
	keyName  = ".gkeeper.key.pem"
	confName = ".gkeeper"
)

var (
	auth       string
	certFile   string
	clientAuth string
	configFile string
	keyFile    string
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
	flag.StringVar(&certFile, "cert-file", "", "the TLS certificate file to use")
	get := flag.Bool("get", false, "get data")
	flag.StringVar(&keyFile, "key-file", "", "the TLS key file to use")
	asServer := flag.Bool("server", false, "run in server mode")
	set := flag.Bool("set", false, "set the password")
	flag.BoolVar(&verbose, "verbose", false, "enable debugging")
	flag.Parse()
	setConfig()
	if *asServer {
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
