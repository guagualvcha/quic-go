package t_test

import (
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	"github.com/lucas-clemente/quic-go"
)

const addr = "localhost:42441"

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
var listener quic.Listener

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func Aini() {
	var err error
	fmt.Println("Execute init")
	listener, err = quic.ListenAddr(addr, generateTLSConfig(), nil)
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			sess, err := listener.Accept()
			if err != nil {
				panic(err)
			}
			stream, err := sess.AcceptStream()
			if err != nil {
				panic(err)
			}
			go func() {
				a := make([]byte, 1024)
				_,err:= stream.Read(a)
				if err!=nil{
					panic(err)
				}
			}()
		}
	}()
}


// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func BenchmarkSecretConnection(b *testing.B) {
	b.StopTimer()
	Aini()
	session, err := quic.DialAddr(addr, &tls.Config{InsecureSkipVerify: true}, nil)
	if err != nil {
		panic(err)
	}

	stream, err := session.OpenStreamSync()
	if err != nil {
		panic(err)
	}

	message := randSeq(1024)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err = stream.Write([]byte(message))
		if err != nil {
			panic(err)
		}
	}
	b.StopTimer()
	if err != nil {
		panic(err)
	}
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
