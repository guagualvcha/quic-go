package main

import (
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"math/big"
	"math/rand"
	"net/http"
	"sync"
	"time"

	_ "net/http/pprof"
)

const addr = "localhost:4242"

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	go http.ListenAndServe(":6666", nil)
	go echoServer()

	err := clientMain()
	if err != nil {
		panic(err)
	}
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func clientMain() error {
	session, err := quic.DialAddr(addr, &tls.Config{InsecureSkipVerify: true}, nil)
	if err != nil {
		return err
	}
	message := randSeq(1024)

	stream, err := session.OpenStreamSync()
	if err != nil {
		return err
	}
	fmt.Printf("Client: Sending '%s'\n", message)
	start := time.Now()
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		for i := 0; i < 200000000; i++ {
			buf := make([]byte, len(message))
			_, err = stream.Read(buf)
			if err != nil {
				panic(err)
			}
		}
		wg.Done()
	}()

	for i := 0; i < 200000000; i++ {
		_, err = stream.Write([]byte(message))
		if err != nil {
			return err
		}
	}
	wg.Wait()
	dur := time.Now().Sub(start)
	fmt.Println(dur)
	return nil
}

// Start a server that echos all data on the first stream opened by the client
func echoServer() error {
	listener, err := quic.ListenAddr(addr, generateTLSConfig(), nil)
	if err != nil {
		return err
	}

	for {
		sess, err := listener.Accept()
		if err != nil {
			return err
		}
		stream, err := sess.AcceptStream()
		if err != nil {
			panic(err)
		}
		// Echo through the loggingWriter
		go func() {
			for {
				start := time.Now()
				a := make([]byte, 1024)
				_, err := stream.Read(a)
				if err != nil {
					fmt.Println(time.Now().Sub(start))
					return
				}
				stream.Write(a)
			}
		}()
	}
	return nil
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(crand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(crand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}
}
