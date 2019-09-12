# stash

A server/client for storing an encrypted password in memory. Written in Go.

## Installation

To install the tool using `Go` like so:

`$ go get github.com/walkert/stash`


## Details

I wrote `stash` as a purely localhost solution for password vault storage. That being said, it is intended to be secure enough for both local and remote use (where the client/server are separated across the network).

### Server mode

`stash` operates as both a server and a client. When in server mode, it will start a TLS-enabled gRPC server that is capable of storing and retrieving a string (typically a password). When a client sets a password for the first time, it sends through an authentication token which all future `get` operations must send in order to communicate with the server. The server encrypts the password using a randomly generated salt and password and will then continue to re-encrypt the data every five seconds.

### Client mode

When `stash` sets a password for the first time, it will encrypt it locally with a random salt and password before sending it to the server. It will then store the salt, password and a randomly generated authentication token locally in an obfuscated string. When getting a password, the client will read the locally stored token and use it to authenticate with the server before decrypting the received string with the locally stored salt/password.

## Setup

Since `stash` uses TLS by default, you will need to generate an SSL certificate and key file. Both will be used by the server while the client will just need to use the certificate.

To generate the keypair you can run the following command (note this assumes you're running the server listening on localhost):

```shell
$ openssl req -x509 -newkey rsa:4096 -keyout ~/.stash.key.pem -out ~/.stash.cert.pem -days 365 -nodes -subj '/CN=localhost'
```

## Starting the server

The simplest way to get started is running with all of the defaults set (listen on localhost:2002, use the default key/cert names (see above), set the expiration time to 12 hours).

```shell
$ stash --server --daemon
```

## Using the client

Client usage is simple. You either set a password, or get it/validate that one is set.

### Setting a password

```shell
$ stash --set
Password: ************
```

### Checking to see if a password is set

The `validate` option will print the password if one is set or report and error if not.

```shell
$ stash --get --validate
Password not set
```

### Get the password

When the password is printed to a terminal device, it is obscured by setting the background/foregound colour to silver. This prevents people looking over your shoulder but the text can still be copied. The preferred method of usage is to pipe the output to a utility such as `pbcopy` on OSX.

```shell
$ stash --get
###############
```
